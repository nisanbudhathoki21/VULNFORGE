from vulnforge.core.authorization import AuthorizationContext
from vulnforge.engine.orchestrator import ScanConfig, run_scan
from vulnforge.core.store import Store


def test_stop_file_safely_persists(monkeypatch,tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path/".vulnforge-stop").write_text("stop")
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
    result=run_scan(ScanConfig(target="http://127.0.0.1:1/",profile_name="passive",allowed_hosts=["127.0.0.1"],allow_private=True,authorization_confirmed=True),auth)
    assert result.aborted
    st=Store(str(tmp_path/"state.db")); st.save_scan(result)
    assert st.get_scan(result.context.scan_id)["status"] == "aborted"
    assert result.context.stats.requests_sent == 0
