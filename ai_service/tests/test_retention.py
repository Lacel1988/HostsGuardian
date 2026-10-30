import asyncio
from datetime import datetime,timedelta,timezone
import logging
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from test_gate1 import offline
from hostsguardian_ai.api import create_app
from hostsguardian_ai.config import Settings
from hostsguardian_ai.retention import FILES, LogEvent, MetadataErrorHandler, RetentionStore
from hostsguardian_ai.schemas import Outcome


def make_store(tmp_path,**settings):
    now=[datetime(2026,10,30,12,tzinfo=timezone.utc)]
    store=RetentionStore(Settings(**settings),tmp_path,lambda:now[0])
    store.cleanup()
    return store,now


@pytest.mark.parametrize("kind,hours",[("dns_activity",168),("device_identity",168),("diagnostic",168),("ai_error",48)])
def test_each_event_timestamp_expires_individually_on_startup(tmp_path,kind,hours):
    store,now=make_store(tmp_path)
    store.record(kind,"workflow",Outcome.SUCCESS,timestamp=now[0]-timedelta(hours=hours)+timedelta(seconds=1))
    store.record(kind,"workflow",Outcome.UNAVAILABLE,timestamp=now[0]-timedelta(hours=hours)+timedelta(hours=2))
    # File modification time must not determine record expiration.
    path=tmp_path/FILES[kind]
    os.utime(path,(0,0))
    now[0]+=timedelta(seconds=2)
    restarted=RetentionStore(Settings(),tmp_path,lambda:now[0])
    restarted.cleanup()
    events=restarted.read(kind)
    assert len(events)==1 and events[0].status==Outcome.UNAVAILABLE
    assert restarted.expired==1


async def test_periodic_expiration_without_new_requests(tmp_path):
    store,now=make_store(tmp_path,retention_cleanup_seconds=.02)
    store.record("ai_error","workflow",Outcome.INVALID)
    task=asyncio.create_task(store.periodic())
    try:
        now[0]+=timedelta(hours=49)
        await asyncio.sleep(.08)
        assert not store.read("ai_error") and store.expired==1
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task


def test_caps_and_compaction_preserve_newest_individual_timestamps(tmp_path):
    store,now=make_store(tmp_path,retention_max_file_bytes=8192,retention_max_total_bytes=16384,retention_max_events=5)
    for kind in FILES:
        # Out-of-order arrivals must not evict the newest event in favor of stale arrivals.
        for i in range(35):
            store.record(kind,"workflow",Outcome.SUCCESS,timestamp=now[0]-timedelta(seconds=i))
    store.cleanup()
    for kind in FILES:
        events=store.read(kind)
        assert len(events)==5
        assert {e.timestamp for e in events}=={now[0]-timedelta(seconds=i) for i in range(5)}
        assert (tmp_path/FILES[kind]).stat().st_size<=4096
    assert sum((tmp_path/name).stat().st_size for name in FILES.values())<=16384
    assert store.file_cap*(len(FILES)+1)<=16384  # Includes one active compaction temp.
    assert not list(tmp_path.glob("*.tmp"))


def test_configuration_policy_and_unknown_files_are_never_touched(tmp_path):
    protected={name:b'protected security state' for name in ("config.json","policy.json","id_ed25519","index.json","config.json.tmp")}
    for name,data in protected.items(): (tmp_path/name).write_bytes(data)
    store,now=make_store(tmp_path)
    store.record("diagnostic","workflow",Outcome.SUCCESS)
    now[0]+=timedelta(days=8)
    store.cleanup()
    for name,data in protected.items(): assert (tmp_path/name).read_bytes()==data
    assert not store.read("diagnostic")


def test_unrecognized_owned_name_and_hardlinks_fail_closed(tmp_path):
    directory=tmp_path/"logs";directory.mkdir()
    config=tmp_path/"config.json";config.write_bytes(b'{"important":"preserve"}')
    path=directory/FILES["diagnostic"]
    path.write_bytes(config.read_bytes())
    store=RetentionStore(Settings(),directory)
    store.cleanup()
    assert not store.available and path.read_bytes()==config.read_bytes()
    store.record("diagnostic","workflow",Outcome.INVALID)
    assert path.read_bytes()==config.read_bytes()
    # Replace only this test-owned fixture with a real hardlink.
    path.unlink();os.link(config,path)
    store.cleanup();store.record("diagnostic","workflow",Outcome.INVALID)
    assert not store.available and config.read_bytes()==b'{"important":"preserve"}'


def test_reparse_paths_rejected_before_cleanup(tmp_path,monkeypatch):
    directory=tmp_path/"logs";directory.mkdir()
    real=Path.lstat
    def fake(path):
        if path==directory:
            return type("Junction",(),{"st_mode":0o040755,"st_file_attributes":0x400})()
        return real(path)
    monkeypatch.setattr(Path,"lstat",fake)
    store=RetentionStore(Settings(),directory)
    store.cleanup()
    assert not store.available and not list(directory.iterdir())


def test_unknown_temporary_file_cannot_be_mistaken_for_disposable_log_data(tmp_path):
    temporary=tmp_path/(FILES["diagnostic"]+".tmp")
    original=b'{"security_state":"must survive"}'
    temporary.write_bytes(original)
    store=RetentionStore(Settings(),tmp_path)
    store.cleanup()
    assert not store.available and temporary.read_bytes()==original
    store.record("ai_error","workflow",Outcome.INVALID)
    assert store.read("ai_error") and temporary.read_bytes()==original


def test_error_handler_records_no_message_prompt_evidence_or_credentials(tmp_path):
    store,_=make_store(tmp_path)
    handler=MetadataErrorHandler(store)
    event=logging.LogRecord("hostsguardian_ai",logging.ERROR,__file__,1,
        "sentinel-secret user-question raw-evidence",(),None)
    # Use the controlled fixture clock, not the host's date.
    event.created=store.clock().timestamp()
    handler.emit(event)
    raw=(tmp_path/FILES["ai_error"]).read_text()
    for text in ("sentinel-secret","user-question","raw-evidence"):
        assert text not in raw
    assert len(store.read("ai_error"))==1
    with pytest.raises(ValidationError):
        LogEvent(kind="ai_error",timestamp=store.clock(),source="workflow",status="error",prompt="secret")
    store.record("ai_error","workflow",Outcome.INVALID,reason_code="sentinel-secret")
    assert "sentinel-secret" not in (tmp_path/FILES["ai_error"]).read_text()


def test_application_lifespan_enables_retention_and_persists_only_metadata(tmp_path,monkeypatch):
    import hostsguardian_ai.api as api
    store=RetentionStore(Settings(),tmp_path)
    monkeypatch.setattr(api,"RetentionStore",lambda settings:store)
    with TestClient(create_app(Settings(provider="mock"))) as client:
        response=client.post("/v1/analyst",json={"question":"Why is DNS failing?","language":"hu"})
        assert response.status_code==200
        assert client.get("/v1/ready").json()["dependencies"]["log_retention"]=="ready"
    raw="".join(path.read_text() for path in tmp_path.glob("*.jsonl"))
    assert "Why is DNS failing?" not in raw and "Fixture Engine" not in raw
    assert store.read("device_identity") and store.read("dns_activity") and store.read("diagnostic")


def test_arbitrary_categories_and_retention_bounds_rejected(tmp_path):
    store,_=make_store(tmp_path)
    with pytest.raises(ValidationError): store.record("config","workflow",Outcome.SUCCESS)
    with pytest.raises(ValueError): store.record("diagnostic","arbitrary-path",Outcome.SUCCESS)
    for args in ({"ai_error_retention_hours":0},{"retention_max_total_bytes":1024},{"retention_cleanup_seconds":0}):
        with pytest.raises(ValidationError): Settings(**args)
