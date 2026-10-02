/* Structured, inert views over a persisted VULNFORGE HTTP exchange. */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.VulnForgeTrafficInspector = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function bodyOf(exchange, side) {
    return String(exchange?.[side === 'request' ? 'request_body' : 'response_body'] ?? '');
  }

  function headerPairs(exchange, side) {
    const prefix = side === 'request' ? 'request' : 'response';
    const items = exchange?.[`${prefix}_header_items`];
    if (Array.isArray(items)) {
      return items.filter((item) => Array.isArray(item) && item.length >= 2)
        .map(([name, value]) => [String(name), String(value)]);
    }
    const headers = exchange?.[`${prefix}_headers`];
    if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return [];
    return Object.entries(headers).map(([name, value]) => [String(name), String(value)]);
  }

  function asLines(items, empty) {
    return items.length ? items.map(([name, value]) => `${name}: ${value}`).join('\n') : empty;
  }

  function parsedUrl(exchange) {
    try { return new URL(String(exchange?.url || '')); } catch { return null; }
  }

  function formatRaw(exchange, side, rawRenderer) {
    if (typeof rawRenderer === 'function') return rawRenderer(exchange);
    return side === 'request' ? 'Raw request view unavailable.' : 'Raw response view unavailable.';
  }

  function formatHeaders(exchange, side) {
    return asLines(headerPairs(exchange, side), 'No stored headers.');
  }

  function formatQuery(exchange) {
    const url = parsedUrl(exchange);
    if (!url || !url.search) return 'No query parameters were recorded.';
    return Array.from(url.searchParams.entries())
      .map(([key, value], index) => `${index + 1}. ${key} = ${value}`).join('\n');
  }

  function formatPath(exchange) {
    const url = parsedUrl(exchange);
    if (!url) return 'Stored URL is unavailable or invalid.';
    const segments = url.pathname.split('/').filter(Boolean);
    return [
      `Origin: ${url.origin}`,
      `Path: ${url.pathname || '/'}`,
      `Segments: ${segments.length ? segments.map((segment, index) => `${index + 1}. ${segment}`).join('\n') : '(root)'}`,
      'Path segments are observed literally; identifier/parameter meaning is not inferred.'
    ].join('\n');
  }

  function formatCookies(exchange, side) {
    const wanted = side === 'request' ? new Set(['cookie']) : new Set(['set-cookie']);
    const cookies = headerPairs(exchange, side).filter(([name]) => wanted.has(name.toLowerCase()));
    return asLines(cookies, side === 'request' ? 'No Cookie header was stored.' : 'No Set-Cookie header was stored.');
  }

  function formatBody(exchange, side) {
    const body = bodyOf(exchange, side);
    return body || (side === 'request' ? 'No request body was stored.' : 'No response body was stored.');
  }

  function formatJson(exchange, side) {
    const body = bodyOf(exchange, side);
    if (!body.trim()) return 'No body was stored.';
    try { return JSON.stringify(JSON.parse(body), null, 2); }
    catch { return 'Stored body is not valid JSON. Use the Body view to inspect it as text.'; }
  }

  function formatOverview(exchange, side) {
    const url = parsedUrl(exchange);
    const headers = headerPairs(exchange, side);
    const body = bodyOf(exchange, side);
    if (side === 'request') {
      return [`Method: ${exchange?.method || 'Not recorded'}`, `URL: ${exchange?.url || 'Not recorded'}`, `Host: ${url?.host || 'Not recorded'}`, `Path: ${url?.pathname || '/'}`, `Query parameters: ${url?.searchParams?.size || 0}`, `Headers: ${headers.length}`, `Body: ${body ? `${body.length} characters` : 'empty'}`, `Authentication context: ${exchange?.authentication_context_id || 'Not recorded'}`, `Source: ${exchange?.module || exchange?.source || 'Not recorded'}`, `Timestamp: ${exchange?.timestamp || 'Not recorded'}`].join('\\n');
    }
    return [`Status: ${exchange?.status || 'No response'}`, `Reason: ${exchange?.reason_phrase || 'Not recorded'}`, `Content-Type: ${headers.find(([name]) => name.toLowerCase() === 'content-type')?.[1] || 'Not recorded'}`, `Content-Length: ${body.length} bytes`, `Response time: ${exchange?.duration_ms ?? 'Not recorded'} ms`, `Server: ${headers.find(([name]) => name.toLowerCase() === 'server')?.[1] || 'Not recorded'}`, `Redirect: ${headers.find(([name]) => name.toLowerCase() === 'location')?.[1] || 'None'}`].join('\\n');
  }

  function formatAuthentication(exchange) {
    const headers = headerPairs(exchange, 'request').filter(([name]) => /authorization|cookie|token|session/i.test(name));
    return headers.length ? headers.map(([name, value]) => `${name}: ${value}`).join('\\n') : 'No authentication headers were recorded. Sensitive values are redacted by default.';
  }

  function formatHistory(exchange) {
    return [`Exchange: ${exchange?.exchange_id || 'Not recorded'}`, `Parent exchange: ${exchange?.parent_exchange_id || 'None'}`, `Request ID: ${exchange?.request_id || 'Not recorded'}`, `Response ID: ${exchange?.response_id || 'Not recorded'}`, `Module: ${exchange?.module || 'Not recorded'}`].join('\\n');
  }

  function formatLinked(exchange, kind) {
    const values = exchange?.[`${kind}_ids`] || exchange?.[`${kind}_id`];
    return values ? JSON.stringify(values, null, 2) : `No ${kind} links were stored for this exchange.`;
  }

  function formatTiming(exchange) {
    const duration = Number(exchange?.duration_ms);
    const requestBytes = new TextEncoder().encode(bodyOf(exchange, 'request')).length;
    const responseBytes = new TextEncoder().encode(bodyOf(exchange, 'response')).length;
    const status = Number(exchange?.status || 0);
    return [
      `Status: ${status > 0 ? `HTTP ${status}` : 'No response recorded'}`,
      `Duration: ${Number.isFinite(duration) && duration >= 0 ? `${duration.toFixed(1)} ms` : 'Not recorded'}`,
      `Request body: ${requestBytes} bytes${exchange?.request_body_truncated ? ' (truncated)' : ''}`,
      `Response body: ${responseBytes} bytes${exchange?.response_body_truncated ? ' (truncated)' : ''}`,
      `Request ID: ${exchange?.request_id || 'Not recorded'}`,
      `Response ID: ${exchange?.response_id || 'Not recorded'}`,
      `Exchange ID: ${exchange?.exchange_id || 'Not recorded'}`,
      `Module: ${exchange?.module || 'Not recorded'}`,
      `Error: ${exchange?.error || 'None recorded'}`
    ].join('\n');
  }

  function render(exchange, side, view, rawRenderer) {
    if (!exchange || !['request', 'response'].includes(side)) return 'No exchange selected.';
    switch (view) {
      case 'overview': return formatOverview(exchange, side);
      case 'raw': return formatRaw(exchange, side, rawRenderer);
      case 'headers': return formatHeaders(exchange, side);
      case 'query': return side === 'request' ? formatQuery(exchange) : 'Query parameters belong to the request URL.';
      case 'path': return side === 'request' ? formatPath(exchange) : 'Path details belong to the request URL.';
      case 'cookies': return formatCookies(exchange, side);
      case 'body': return formatBody(exchange, side);
      case 'json': return formatJson(exchange, side);
      case 'timing': return formatTiming(exchange);
      case 'authentication': return side === 'request' ? formatAuthentication(exchange) : 'Authentication context belongs to the request.';
      case 'history': return formatHistory(exchange);
      case 'tests': return formatLinked(exchange, 'test');
      case 'evidence': return formatLinked(exchange, 'evidence');
      case 'diff': return 'Select another stored exchange in the comparison panel below to view a persisted differential. Differences are not vulnerability verdicts.';
      default: return `Unsupported ${side} view: ${view}`;
    }
  }

  return { render, headerPairs, formatQuery, formatPath, formatCookies, formatJson, formatTiming };
});
