"""Node-level contract tests for the real-data HTTP inspector formatter."""
from pathlib import Path
import shutil
import subprocess

import pytest

NODE = shutil.which("node")
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(NODE is None, reason="Node.js is required for dashboard helper tests")
def test_inspector_views_render_observed_exchange_fields_as_text():
    module = ROOT / "vulnforge" / "dashboard_static" / "traffic_inspector.js"
    script = r"""
const assert = require('node:assert/strict');
const inspector = require(process.argv[1]);
const exchange = {
  exchange_id: 'ex-1', request_id: 'rq-1', response_id: 'rs-1', module: 'test-module',
  method: 'POST', url: 'https://authorized.test/api/items/42?tag=a&tag=b',
  status: 200, duration_ms: 12.34,
  request_headers: {'Content-Type': 'application/json', 'Cookie': 'sid=[REDACTED]'},
  response_headers: {'Content-Type': 'application/json', 'Set-Cookie': 'sid=[REDACTED]; HttpOnly'},
  request_body: '{"name":"sample"}', response_body: '{"ok":true}',
};
assert.match(inspector.render(exchange, 'request', 'query'), /tag = a[\s\S]*tag = b/);
assert.match(inspector.render(exchange, 'request', 'path'), /\/api\/items\/42/);
assert.match(inspector.render(exchange, 'request', 'cookies'), /sid=\[REDACTED\]/);
assert.equal(inspector.render(exchange, 'request', 'json'), '{\n  "name": "sample"\n}');
assert.match(inspector.render(exchange, 'response', 'headers'), /Content-Type: application\/json/);
assert.equal(inspector.render(exchange, 'response', 'json'), '{\n  "ok": true\n}');
assert.match(inspector.render(exchange, 'response', 'timing'), /12\.3 ms/);
assert.match(inspector.render({...exchange, response_body: '<script>not executed</script>'}, 'response', 'body'), /^<script>/);
assert.match(inspector.render(exchange, 'request', 'raw', () => 'REAL RAW REQUEST'), /REAL RAW REQUEST/);
assert.equal(inspector.render(exchange, 'sideways', 'raw'), 'No exchange selected.');
"""
    result = subprocess.run(
        [NODE, "-e", script, str(module)], cwd=ROOT,
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr or result.stdout
