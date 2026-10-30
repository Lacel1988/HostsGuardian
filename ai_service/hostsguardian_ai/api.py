import asyncio
import re
import contextlib
import logging
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .config import Settings
from .diagnostics import DiagnosticTools, MockDiagnostics
from .providers import ModelProvider, MockProvider, OllamaProvider
from .schemas import InvestigationRequest, InvestigationResponse, Outcome
from .workflow import build_workflow, build_adaptive_workflow
from .analyst_contracts import AnalystRequest, AnalystResponse
from .orchestration import WorkflowError
from .retrieval.contracts import RetrievalError, RetrievalRequest, RetrievalResponse
from .retrieval.service import Retrieval, RetrievalService
from .retrieval.embeddings import LocalEmbedder
from .retrieval.index import load
from .retention import RetentionStore, MetadataErrorHandler
from .engine import EngineConfig, EngineDiagnosticsAdapter, read_secret


def error(status: int, code: str):
    return JSONResponse(status_code=status, content={"schema_version": 1, "error": {"code": code}})


def create_app(settings: Settings | None = None, tools: DiagnosticTools | None = None,
               provider: ModelProvider | None = None, retrieval: Retrieval | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.engine_live_enabled and tools is None:
        tools=EngineDiagnosticsAdapter(EngineConfig(origin=settings.engine_origin,certificate_file=settings.engine_certificate_file,
            certificate_sha256=settings.engine_certificate_sha256,token_file=settings.engine_token_file,token_format=settings.engine_token_format,
            timeout=settings.engine_timeout,max_age_seconds=settings.engine_max_age_seconds))
    client_token=None
    if isinstance(tools,EngineDiagnosticsAdapter):
        if settings.ai_client_token_file is None:
            raise ValueError("Live Engine diagnostics require separate AI client authentication")
        client_token=read_secret(settings.ai_client_token_file)
        if hmac.compare_digest(client_token.get_secret_value(),read_secret(tools.config.token_file,tools.config.token_format).get_secret_value()):
            raise ValueError("AI and Engine credentials must be separate")
    provider = provider or (MockProvider() if settings.provider == "mock" else OllamaProvider(settings))
    workflow = build_workflow(settings, tools or MockDiagnostics())
    active = 0
    retrieval_state = "not_configured"
    local_embedder = None
    analyst = None
    retention = RetentionStore(settings)

    def record_result(response):
        if getattr(response, "context_response_id", None):
            return
        failures = {f.source: f for f in getattr(response, "failures", ())}
        for source in getattr(response, "tools_used", ("workflow",)):
            failure = failures.get(source)
            kind = "device_identity" if source == "device_identity_status" else "dns_activity" if source == "dns_activity_summary" else "diagnostic"
            retention.record(kind, source, failure.status if failure else Outcome.SUCCESS,
                             reason_code=failure.reason_code if failure else None,
                             evidence_count=min(24, len(getattr(response, "evidence", ()))))
        for failure in failures.values():
            if failure.source == "local_generation":
                retention.record("ai_error", failure.source, failure.status, reason_code=failure.reason_code)

    @asynccontextmanager
    async def lifespan(app):
        # No network probes, Engine initialization or model loading on startup.
        nonlocal retrieval, retrieval_state, local_embedder, analyst
        if retrieval is not None:
            retrieval_state = "ready"
        elif settings.retrieval_index is not None and settings.embedding_model_path is not None:
            try:
                local_embedder = await asyncio.to_thread(LocalEmbedder, settings.embedding_model_path,
                                                        settings.request_timeout)
                snapshot = await asyncio.to_thread(load, settings.retrieval_index, local_embedder.identifier,
                                                   settings.retrieval_corpus_version)
                retrieval = RetrievalService(snapshot, local_embedder, settings.retrieval_rrf_constant,
                    settings.retrieval_min_similarity, settings.request_timeout, settings.max_concurrent_investigations)
                retrieval_state = "index_ready_model_not_probed"
            except RetrievalError as exc:
                retrieval_state = exc.code
        analyst = build_adaptive_workflow(settings, tools or MockDiagnostics(), retrieval, provider)
        await asyncio.to_thread(retention.cleanup)
        cleanup_task = asyncio.create_task(retention.periodic(analyst.prune_context))
        error_handler = MetadataErrorHandler(retention)
        loggers = [logging.getLogger("hostsguardian_ai"), logging.getLogger("uvicorn.error")]
        for logger in loggers:
            logger.addHandler(error_handler)
        try:
            yield
        finally:
            analyst.clear_context()
            for logger in loggers:
                logger.removeHandler(error_handler)
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task
            if local_embedder is not None:
                await asyncio.to_thread(local_embedder.close)

    app = FastAPI(title="HostsGuardian AI", version="0.1.0", lifespan=lifespan)
    app.state.retention = retention

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if client_token is not None and request.url.path!="/v1/health":
            headers=request.headers.getlist("authorization")
            expected="Bearer "+client_token.get_secret_value()
            if len(headers)!=1 or not hmac.compare_digest(headers[0],expected):
                return error(401,"unauthorized")
        if not re.fullmatch(r"(127\.0\.0\.1|localhost|testserver|\[::1\])(:[0-9]{1,5})?", request.headers.get("host", "")):
            return error(400, "host_not_permitted")
        # Reject browser-origin calls: local service has no cross-origin UI in Gate 1.
        if request.headers.get("origin") is not None:
            return error(403, "origin_not_permitted")
        # Stream-count input, including bodies without Content-Length.
        body = bytearray()
        try:
            deadline = settings.workflow_timeout if request.url.path == "/v1/analyst" else settings.request_timeout
            async with asyncio.timeout(deadline):
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 4096:
                        return error(413, "request_too_large")
                request._body = bytes(body)
                return await call_next(request)
        except TimeoutError:
            retention.record("ai_error", "http_api", Outcome.TIMEOUT, reason_code="request_timeout")
            return error(504, "request_timeout")
        except Exception:
            retention.record("ai_error", "http_api", Outcome.INVALID, reason_code="internal_error")
            return error(500, "internal_error")

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error(422, "invalid_request")

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return error(exc.status_code, "http_error")

    @app.get("/v1/health")
    async def health():
        return {"schema_version": 1, "status": "alive"}

    @app.get("/v1/ready")
    async def ready():
        try:
            outcome = await asyncio.wait_for(provider.availability(), timeout=min(2, settings.request_timeout / 2))
        except TimeoutError:
            outcome = Outcome.TIMEOUT
        except Exception:
            outcome = Outcome.UNAVAILABLE
        return {"schema_version": 1, "status": "ready", "mode": "authenticated-engine-readonly" if client_token else "mock-diagnostics",
                "dependencies": {"engine": "configured_not_probed" if client_token else "not_configured", "retrieval": retrieval_state,
                                 "log_retention": "ready" if retention.available else "unavailable",
                                 "model": {"provider": provider.identifier, "outcome": outcome,
                                           "required": False}}}

    @app.post("/v1/investigations", response_model=InvestigationResponse)
    async def investigate(body: InvestigationRequest):
        nonlocal active
        # No await between check and increment: atomic within this single event loop.
        if active >= settings.max_concurrent_investigations:
            return error(429, "investigation_capacity")
        active += 1
        try:
            async with asyncio.timeout(settings.request_timeout):
                state = await workflow.ainvoke({"query": body.query}, {"recursion_limit": 5})
                retention.record("diagnostic", "workflow", Outcome.SUCCESS, evidence_count=min(24,len(state["response"].evidence)))
                return state["response"]
        except TimeoutError:
            return error(504, "investigation_timeout")
        finally:
            active -= 1

    @app.post("/v1/retrieval/search", response_model=RetrievalResponse)
    async def search(body: RetrievalRequest):
        if retrieval is None:
            return error(503, "retrieval_unavailable")
        try:
            response = await retrieval.search(body)
            retention.record("diagnostic", "knowledge_retrieval", Outcome.SUCCESS)
            return response
        except RetrievalError as exc:
            status = 429 if exc.code == "embedding_busy" else 504 if exc.code == "embedding_timeout" else 503
            return error(status, exc.code)

    @app.post("/v1/analyst", response_model=AnalystResponse)
    async def analyze(body: AnalystRequest):
        nonlocal analyst
        if analyst is None:
            analyst = build_adaptive_workflow(settings, tools or MockDiagnostics(), retrieval, provider)
        try:
            response = await analyst.run(body)
            record_result(response)
            return response
        except WorkflowError as exc:
            retention.record("ai_error", "workflow", Outcome.TIMEOUT if exc.code == "workflow_timeout" else Outcome.UNAVAILABLE,
                             reason_code=exc.code)
            status = 429 if exc.code == "workflow_capacity" else 504
            return error(status, exc.code)

    return app
