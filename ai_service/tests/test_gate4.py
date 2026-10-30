import asyncio
from datetime import datetime,timedelta,timezone
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hostsguardian_ai.api import create_app
from hostsguardian_ai.analyst_contracts import AnalystRequest
from hostsguardian_ai.config import Settings
from hostsguardian_ai.engine import EngineConfig,EngineDiagnosticsAdapter,EngineHTTPS,EngineReadError,PATHS
from hostsguardian_ai.orchestration import Analyst
from hostsguardian_ai.providers import MockProvider
from hostsguardian_ai.schemas import Outcome,ToolName


def payloads(now=None):
    now=now or datetime.now(timezone.utc)
    return {"/health":{"ok":True,"engine":"HostsGuardian.DnsEngine","apiVersion":1},
        "/dns/status":{"snapshotUtc":now.isoformat(),"instanceId":"fixture-instance","dnsPort":53,
            "udpListening":True,"tcpListening":True,"filteringEnabled":True,"emergencySafeMode":False,
            "policyRevision":7,"upstreamHealth":"Healthy"},
        "/v2/policy":{"revision":7,"instanceId":"fixture-instance","policy":{"schemaVersion":3,
            "globalBlockedDomains":["fixture.invalid"],"devices":[],"overrides":[]}},
        "/v2/bindings":{"generation":3,"observations":[{"address":"192.0.2.8","networkScope":"fixture-lan",
            "deviceId":"00000000-0000-0000-0000-000000000001","observedAtUtc":now.isoformat(),
            "expiresAtUtc":(now+timedelta(seconds=30)).isoformat(),"validated":True}]},
        "/v3/activity":{"schemaVersion":1,"observedAtUtc":now.isoformat(),"retentionHours":24,"maximumBuckets":256,
            "buckets":[{"windowStartUtc":now.isoformat(),"allowed":5,"blocked":3,"failed":1}]}}


class FixtureClient:
    def __init__(self,data=None,errors=None):
        self.data=data or payloads()
        self.errors=errors or {}
        self.calls=[]
    async def get(self,path):
        assert path in PATHS
        self.calls.append(("GET",path))
        if path in self.errors: raise self.errors[path]
        return self.data[path],datetime.now(timezone.utc)


def config(tmp_path,origin="https://127.0.0.1:3000"):
    token=tmp_path/"engine-token";token.write_text("a"*64)
    return EngineConfig(origin=origin,certificate_file=tmp_path/"cert.pem",certificate_sha256="0"*64,token_file=token)


@pytest.fixture(autouse=True)
def block_non_loopback(monkeypatch):
    real=socket.socket.connect
    def connect(sock,address):
        if isinstance(address,tuple) and address[0] not in ("127.0.0.1","::1"):
            raise AssertionError("No non-loopback access in Gate 4 tests")
        return real(sock,address)
    monkeypatch.setattr(socket.socket,"connect",connect)


@pytest.mark.parametrize("origin",["http://192.0.2.10:3000","https://example.com:3000","https://8.8.8.8:3000",
    "https://192.0.2.10","https://u:p@192.0.2.10:3000","https://192.0.2.10:3000/path","https://192.0.2.10:3000?x=y"])
def test_origin_requires_explicit_private_https(tmp_path,origin):
    with pytest.raises((ValidationError,ValueError)): config(tmp_path,origin)


@pytest.mark.parametrize("tool",list(ToolName))
async def test_mocked_contracts_have_exact_provenance_and_no_writes(tmp_path,tool):
    client=FixtureClient();adapter=EngineDiagnosticsAdapter(config(tmp_path),client)
    result=await adapter.read(tool)
    assert result.outcome==Outcome.SUCCESS and result.evidence
    assert all(method=="GET" and path in PATHS for method,path in client.calls)
    assert all(e.received_at and e.source_reference.startswith(adapter.config.origin) for e in result.evidence)
    if tool==ToolName.DEVICE:
        assert result.evidence[0].verification=="unverified"
        assert result.evidence[0].network_scope=="fixture-lan" and result.evidence[0].valid_until
        assert result.evidence[0].binding_state=="fresh_reported"


@pytest.mark.parametrize("state",["missing","stale","ambiguous","unvalidated"])
async def test_binding_unknown_states_never_become_verified_identity(tmp_path,state):
    data=payloads();rows=data["/v2/bindings"]["observations"]
    if state=="missing": rows.clear()
    elif state=="stale": rows[0]["expiresAtUtc"]=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    elif state=="unvalidated": rows[0]["validated"]=False
    else: rows.append({**rows[0],"deviceId":"00000000-0000-0000-0000-000000000002"})
    result=await EngineDiagnosticsAdapter(config(tmp_path),FixtureClient(data)).read(ToolName.DEVICE)
    assert result.outcome==Outcome.INSUFFICIENT
    assert all(e.verification=="unverified" and e.binding_state==state for e in result.evidence)


@pytest.mark.parametrize("tool,path",[(ToolName.ENGINE,"/dns/status"),(ToolName.ACTIVITY,"/v3/activity")])
async def test_stale_sources_are_not_verified(tmp_path,tool,path):
    data=payloads();key="snapshotUtc" if tool==ToolName.ENGINE else "observedAtUtc"
    data[path][key]=(datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat()
    if path=="/v3/activity": data[path]["buckets"]=[]
    result=await EngineDiagnosticsAdapter(config(tmp_path),FixtureClient(data)).read(tool)
    assert result.outcome==Outcome.INSUFFICIENT and result.reason_code=="adapter:stale_data"
    assert all(e.verification=="unverified" for e in result.evidence)


async def test_inconsistent_policy_revision_and_bad_payload(tmp_path):
    data=payloads();data["/dns/status"]["policyRevision"]=8
    result=await EngineDiagnosticsAdapter(config(tmp_path),FixtureClient(data)).read(ToolName.POLICY)
    assert result.reason_code=="adapter:inconsistent_snapshot" and not result.evidence
    data=payloads();data["/dns/status"]["udpListening"]="true"
    result=await EngineDiagnosticsAdapter(config(tmp_path),FixtureClient(data)).read(ToolName.ENGINE)
    assert result.outcome==Outcome.INVALID and result.reason_code=="adapter:invalid_response"


@pytest.mark.parametrize("code,outcome",[("http:401",Outcome.UNAVAILABLE),("http:403",Outcome.UNAVAILABLE),
    ("adapter:timeout",Outcome.TIMEOUT),("adapter:connection_failed",Outcome.UNAVAILABLE)])
async def test_safe_failure_codes_are_preserved_without_secret_body(tmp_path,code,outcome):
    client=FixtureClient(errors={"/health":EngineReadError(outcome,code)})
    result=await EngineDiagnosticsAdapter(config(tmp_path),client).read(ToolName.ENGINE)
    assert result.outcome==outcome and result.reason_code==code
    assert "a"*64 not in result.model_dump_json()


async def test_live_analyst_keeps_binding_and_enforcement_unknown_and_localizes(tmp_path):
    adapter=EngineDiagnosticsAdapter(config(tmp_path),FixtureClient())
    analyst=Analyst(Settings(),adapter,None,MockProvider())
    hu=await analyst.run(AnalystRequest(question="Why is YouTube not blocked on my TV?",language="hu"))
    assert hu.verified_findings and hu.language=="hu"
    assert "Az Engine szerint" in hu.answer and "nem igazolja" in hu.answer.lower()
    bindings=[e for e in hu.evidence if e.fact_type=="binding_status"]
    assert bindings and all(e.kind=="live_unverified" for e in bindings)
    assert all(next(e for e in hu.evidence if e.evidence_id==p.evidence_id).fact_type!="binding_status" for p in hu.verified_findings)
    assert hu.hypotheses and all(h.status=="unconfirmed" for h in hu.hypotheses)
    followup=await analyst.run(AnalystRequest(question="Why did it fail?",language="en",previous_response_id=hu.response_id))
    assert followup.language=="en" and not followup.verified_findings
    assert all(e.kind!="verified_operational" for e in followup.evidence)
    assert followup.tool_calls==followup.llm_calls==0


def test_live_api_cannot_serve_engine_data_without_separate_client_auth(tmp_path):
    adapter=EngineDiagnosticsAdapter(config(tmp_path),FixtureClient())
    with pytest.raises(ValueError): create_app(Settings(provider="mock"),tools=adapter)
    ai_token=tmp_path/"ai-token";ai_token.write_text("b"*64)
    with TestClient(create_app(Settings(provider="mock",ai_client_token_file=ai_token),tools=adapter)) as client:
        assert client.get("/v1/health").status_code==200
        for route in ("/v1/ready","/openapi.json"):
            assert client.get(route).status_code==401
        assert client.post("/v1/analyst",json={"question":"engine_status"}).status_code==401
        ready=client.get("/v1/ready",headers={"Authorization":"Bearer "+"b"*64}).json()
        assert ready["mode"]=="authenticated-engine-readonly" and ready["dependencies"]["engine"]=="configured_not_probed"
        response=client.post("/v1/analyst",json={"question":"engine_status","language":"hu"},headers={"Authorization":"Bearer "+"b"*64})
        assert response.status_code==200 and response.json()["verified_findings"]
        assert "a"*64 not in response.text and "b"*64 not in response.text
    ai_token.write_text("a"*64)
    with pytest.raises(ValueError): create_app(Settings(ai_client_token_file=ai_token),tools=adapter)


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory):
    directory=tmp_path_factory.mktemp("gate4-tls")
    (directory/"Fixture.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    (directory/"Program.cs").write_text('''using System; using System.IO; using System.Net; using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates;
using var key=RSA.Create(2048);
var request=new CertificateRequest("CN=isolated-fixture",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
var names=new SubjectAlternativeNameBuilder();names.AddIpAddress(IPAddress.Loopback);
request.CertificateExtensions.Add(names.Build());
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new Oid("1.3.6.1.5.5.7.3.1")},true));
using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
File.WriteAllText("cert.pem",certificate.ExportCertificatePem());File.WriteAllText("key.pem",key.ExportPkcs8PrivateKeyPem());''')
    subprocess.run(["dotnet","run","--project","Fixture.csproj"],cwd=directory,check=True,capture_output=True,timeout=60)
    return directory


@pytest.fixture
def https_fixture(tls_files):
    captured=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            captured.append((self.command,self.path,self.headers.get("Authorization")))
            if self.path=="/redirect" or getattr(server,"mode",None)=="redirect":
                self.send_response(302);self.send_header("Location","https://192.0.2.1/secret");self.end_headers();return
            if getattr(server,"mode",None)=="unauthorized":
                self.send_response(401);self.end_headers();return
            if getattr(server,"mode",None)=="duplicate":
                raw=b'{"ok":true,"ok":false}'
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw);return
            data=payloads().get(self.path,{})
            raw=json.dumps(data).encode()
            self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tls_files/"cert.pem",tls_files/"key.pem")
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield server.server_address[1],captured,server
    server.shutdown();server.server_close();thread.join(timeout=2)


async def test_real_loopback_tls_pin_and_auth_before_any_http_bytes(tmp_path,tls_files,https_fixture,monkeypatch):
    port,captured,server=https_fixture
    der=ssl.PEM_cert_to_DER_cert((tls_files/"cert.pem").read_text())
    conf=config(tmp_path,f"https://127.0.0.1:{port}").model_copy(update={"certificate_file":tls_files/"cert.pem","certificate_sha256":hashlib.sha256(der).hexdigest()})
    client=EngineHTTPS(conf)
    raw,_=await client.get("/health")
    assert raw["ok"] and captured==[("GET","/health","Bearer "+"a"*64)]
    for path in ("/safe-mode/enter","/v2/policy/replace","/health?token=secret","https://example.com/","/redirect"):
        with pytest.raises(EngineReadError,match="endpoint_not_allowed"): await client.get(path)
    assert len(captured)==1

    client.config=conf.model_copy(update={"certificate_sha256":"0"*64})
    with pytest.raises(EngineReadError,match="tls:verification_failed"): await client.get("/health")
    assert len(captured)==1


@pytest.mark.parametrize("mode,code",[("redirect","http:302"),("unauthorized","http:401"),("duplicate","adapter:invalid_json")])
async def test_real_transport_rejects_redirect_auth_failure_and_duplicate_json(tmp_path,tls_files,https_fixture,mode,code):
    port,captured,server=https_fixture
    server.mode=mode
    der=ssl.PEM_cert_to_DER_cert((tls_files/"cert.pem").read_text())
    conf=config(tmp_path,f"https://127.0.0.1:{port}").model_copy(update={"certificate_file":tls_files/"cert.pem","certificate_sha256":hashlib.sha256(der).hexdigest()})
    with pytest.raises(EngineReadError,match=code):
        await EngineHTTPS(conf).get("/health")
    assert len(captured)==1 and captured[0][1]=="/health"


async def test_acceptance_collector_sanitizes_snapshots_and_never_claims_pass(tmp_path,monkeypatch):
    from hostsguardian_ai import gate4_acceptance as acceptance
    data=payloads()
    now=datetime.now(timezone.utc).isoformat()
    data["/v2/diagnostics"]={"schemaVersion":1,"instanceId":"fixture-instance","snapshotUtc":now,"health":"Healthy","counters":{}}
    data["/v2/capabilities"]={"apiVersion":2}
    client=FixtureClient(data)
    monkeypatch.setattr(acceptance,"EngineHTTPS",lambda conf:client)
    report=await acceptance.collect(config(tmp_path))
    assert report["gate4"]=="NO-GO" and len(client.calls)==14
    assert all(report["unchanged_fingerprints"].values())
    text=json.dumps(report)
    assert "192.0.2.8" not in text and "fixture.invalid" not in text and "a"*64 not in text


@pytest.mark.parametrize("language,question,expected",[("en","Működik a DNS?","The Engine reports"),("hu","engine_status","Az Engine szerint")])
async def test_live_ui_language_precedence_with_api_facts(tmp_path,language,question,expected):
    analyst=Analyst(Settings(),EngineDiagnosticsAdapter(config(tmp_path),FixtureClient()),None,MockProvider())
    response=await analyst.run(AnalystRequest(question=question,language=language))
    assert response.language==language and expected in response.answer


def test_acceptance_refuses_without_authorization_before_credentials_or_network(monkeypatch):
    from hostsguardian_ai import gate4_acceptance as acceptance
    monkeypatch.setattr("sys.argv",["gate4_acceptance","--origin","https://127.0.0.1:3000",
        "--certificate-file","missing.pem","--certificate-sha256","0"*64,"--token-file","missing-token"])
    monkeypatch.setattr(acceptance,"EngineHTTPS",lambda conf:pytest.fail("Unauthorized transport construction"))
    with pytest.raises(SystemExit) as caught: acceptance.main()
    assert caught.value.code==2


@pytest.mark.parametrize("language",["hu","en"])
async def test_live_failure_explanation_keeps_actual_code_without_invented_cause(tmp_path,language):
    adapter=EngineDiagnosticsAdapter(config(tmp_path),FixtureClient(errors={"/health":EngineReadError(Outcome.UNAVAILABLE,"http:401")}))
    analyst=Analyst(Settings(),adapter,None,MockProvider())
    initial=await analyst.run(AnalystRequest(question="engine_status",language=language))
    assert not initial.verified_findings and initial.failures[0].reason_code=="http:401"
    followup=await analyst.run(AnalystRequest(question="Miért nem sikerült?" if language=="hu" else "Why did it fail?",
        language=language,previous_response_id=initial.response_id))
    assert "http:401" in followup.answer and not followup.verified_findings
    assert followup.tool_calls==0 and followup.language==language


@pytest.mark.parametrize("language",["hu","en"])
async def test_natural_domain_blocking_question_uses_readonly_investigation(tmp_path,language):
    client=FixtureClient()
    analyst=Analyst(Settings(),EngineDiagnosticsAdapter(config(tmp_path),client),None,MockProvider())
    answer=await analyst.run(AnalystRequest(question="Is domain blocking working?",language=language))
    assert answer.route=="investigation" and answer.language==language
    assert answer.verified_findings and answer.unknowns
    assert all(method=="GET" and path in PATHS for method,path in client.calls)
    blocked=await analyst.run(AnalystRequest(question="Disable domain blocking",language=language))
    assert blocked.status=="refused" and blocked.tool_calls==0


def test_identity_and_blocking_query_normalization_is_bilingual():
    from hostsguardian_ai.knowledge import knowledge_query
    from hostsguardian_ai.analyst_contracts import EvidenceRecord
    from hostsguardian_ai.knowledge import supported_clauses
    hu="Miért nem tudod azonosítani ezt az eszközt?"
    en="Why can't you identify this device?"
    assert knowledge_query(hu)==knowledge_query(en)
    text="Bindings need interface scope and fresh identity evidence."
    item=EvidenceRecord(evidence_id="doc:"+"b"*64,kind="approved_documentation",source_reference="corpus://identity.md",
        source_id="a"*64,chunk_id="b"*64,corpus_version="c"*64,timestamp=datetime.now(timezone.utc),content=text,verification="unverified")
    assert "binding" in [c.key for c,_ in supported_clauses([item],hu)]
    assert knowledge_query("Is domain blocking working?")==knowledge_query("Működik a domainblokkolás?")
