(() => {
  'use strict';

  const routeTitles = {
    dashboard: 'Dashboard', 'new-scan': 'New scan', scans: 'Scans & history',
    targets: 'Targets', endpoints: 'Endpoints', parameters: 'Parameters', research: 'Research model', technologies: 'Technologies',
    findings: 'Findings', verified: 'Verified findings', evidence: 'Evidence',
    reports: 'Reports', traffic: 'HTTP traffic', repeater: 'Repeater', console: 'Live console',
    utilities: 'Utilities', events: 'Scan events', settings: 'Settings', 'scan-live': 'Scan progress'
  };
  const state = { activeRoute: 'dashboard', eventSource: null, trafficRefreshTimer: null, activeScanId: '', selectedScanId: '', evidenceFindingId: '', savedScans: [], scanRequestCount: 0, repeaterHistory: [],
    trafficScans: [], trafficScanId: '', trafficItems: [], trafficOffset: 0,
    trafficLimit: 100, trafficHasMore: false, trafficExchangeId: '', selectedExchange: null, workbenchScanId: '', workbenchExchanges: [],
    eventScanId: '', eventItems: [], eventScanStatus: '', storedEventSource: null,
    eventNextCursor: 0, eventHasMore: false,
    parameterScanId: '', parameterItems: [], researchScanId: '', researchItems: [],
    researchOffset: 0, researchHasMore: false,
    inspectorViews: { request: 'raw', response: 'raw' }, repeaterSourceExchangeId: '' };
  const byId = (id) => document.getElementById(id);

  function navigate(route, updateHash = true) {
    if (!Object.hasOwn(routeTitles, route)) route = 'dashboard';
    state.activeRoute = route;
    document.querySelectorAll('[data-view]').forEach((view) => {
      view.classList.toggle('is-visible', view.dataset.view === route);
    });
    document.querySelectorAll('.nav-link[data-route]').forEach((link) => {
      const active = link.dataset.route === route;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    document.querySelectorAll('.workbench-tab[data-route]').forEach((tab) => {
      tab.classList.toggle('is-active', tab.dataset.route === route);
    });
    byId('page-title').textContent = routeTitles[route];
    if (updateHash && location.hash !== `#${route}`) history.replaceState(null, '', `#${route}`);
    closeMobileNav();
    if (route === 'dashboard') loadDashboard();
    if (route === 'scans') loadScansPage();
    if (route === 'targets') loadTargetsPage();
    if (route === 'endpoints') loadEndpointsPage();
    if (route === 'parameters') loadParametersPage();
    if (route === 'research') loadResearchPage(true);
    if (route === 'technologies') loadTechnologiesPage();
    if (route === 'findings') loadFindingsPage(false);
    if (route === 'verified') loadFindingsPage(true);
    if (route === 'evidence') loadEvidencePage();
    if (route === 'reports') loadReportsPage();
    if (route !== 'events' && state.storedEventSource) { state.storedEventSource.close(); state.storedEventSource=null; }
    if (route === 'events') loadEventsPage();
    if (route === 'settings') loadSettingsPage();
    if (route === 'repeater') loadRepeaterHistory();
    if (route !== 'traffic' && state.trafficRefreshTimer) {
      clearInterval(state.trafficRefreshTimer);
      state.trafficRefreshTimer = null;
    }
    if (route === 'traffic') {
      if (!state.trafficScanId && state.workbenchScanId) state.trafficScanId = state.workbenchScanId;
      loadTrafficScans();
      if (!state.trafficRefreshTimer) {
        state.trafficRefreshTimer = setInterval(refreshTrafficIfRunning, 2500);
      }
    }
  }

  function closeMobileNav() {
    byId('sidebar').classList.remove('is-open');
    byId('sidebar-scrim').classList.remove('is-visible');
    byId('menu-toggle').setAttribute('aria-expanded', 'false');
    byId('menu-toggle').setAttribute('aria-label', 'Open navigation');
  }

  async function apiGet(url) {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  }

  async function runUtility(event) {
    event.preventDefault();const button=byId('utility-run'),errorBox=byId('utility-error');errorBox.hidden=true;button.disabled=true;button.textContent='Running…';
    try{const response=await fetch('/api/tools/encode-decode',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({text:byId('utility-input').value,operation:byId('utility-operation').value})});const data=await response.json();if(!response.ok)throw new Error(data.detail||`Request failed (${response.status})`);byId('utility-output').textContent=String(data.result??'');byId('utility-result-meta').textContent=`${data.operation} · local utility API`;}
    catch(error){errorBox.textContent=`Utility failed: ${error.message}`;errorBox.hidden=false;byId('utility-result-meta').textContent='Operation failed.';}
    finally{button.disabled=false;button.textContent='Run utility';}
  }

  async function loadSettingsPage() {
    const grid=byId('settings-grid');grid.replaceChildren();const loading=document.createElement('p');loading.className='muted';loading.textContent='Loading runtime settings…';grid.append(loading);
    try{const data=await apiGet('/api/vf/settings');grid.replaceChildren();const entries=[
      ['Dashboard bind',`${data.runtime?.bind_host||'unknown'}:${data.runtime?.port||'unknown'}`],
      ['Structured scan database',`${data.structured_database?.file||'unknown'} · ${data.structured_database?.status||'status unavailable'}`],
      ['Database permissions',data.structured_database?.permissions||'unavailable'],
      ['Database size',data.structured_database?.size_bytes==null?'Not created':`${Number(data.structured_database.size_bytes).toLocaleString()} bytes`],
      ['Sensitive HTTP history',data.sensitive_http_history],['Traffic representation',data.traffic_capture],
      ['Active verification coverage',data.active_verification],['Configuration',data.configuration_source]
    ];entries.forEach(([label,value])=>{const card=document.createElement('div');card.className='settings-card';const key=document.createElement('span');key.textContent=label;const val=document.createElement('strong');val.textContent=String(value??'Not available');card.append(key,val);grid.append(card);});
    }catch(error){grid.replaceChildren();const msg=document.createElement('p');msg.className='form-error';msg.textContent=`Could not load settings: ${error.message}`;grid.append(msg);}
  }

  function tableMessage(body, columns, message) {
    if (!body) return;
    body.replaceChildren();
    const row=document.createElement('tr'),cell=document.createElement('td');
    cell.colSpan=columns; cell.className='table-empty'; cell.textContent=message;
    row.append(cell); body.append(row);
  }

  function appendCell(row,value,className='') {
    const cell=document.createElement('td'); cell.textContent=(value===null||value===undefined||value==='')?'—':String(value);
    if (className) cell.className=className;
    row.append(cell); return cell;
  }

  function formatDate(value) {
    if (value===null||value===undefined||value==='') return '—';
    const n=Number(value); const date=Number.isFinite(n)?new Date(n*1000):new Date(value);
    return Number.isNaN(date.getTime())?String(value):date.toLocaleString();
  }

  function actionButton(label,handler,className='button button-quiet') {
    const button=document.createElement('button'); button.type='button'; button.className=className;
    button.textContent=label; button.addEventListener('click',handler); return button;
  }

  function scanActionCell(row,scan) {
    const cell=document.createElement('td'); cell.className='action-cell';
    cell.append(actionButton('Details',()=>loadScanDetail(scan.scan_id)));
    cell.append(actionButton('Traffic',()=>{state.trafficScanId=scan.scan_id;navigate('traffic');}));
    row.append(cell);
  }

  async function ensureSavedScans() {
    if (!state.savedScans.length) {
      state.savedScans=await apiGet('/api/vf/scans');
    }
    return state.savedScans;
  }

  async function populateScanSelect(selectId) {
    const select=byId(selectId); if (!select) return;
    try {
      state.savedScans=await apiGet('/api/vf/scans');
      const scans=state.savedScans;
      const prior=select.value;
      select.replaceChildren(new Option('All scans',''));
      scans.forEach(scan=>select.append(new Option(`${scan.target} · ${scan.scan_id}`,scan.scan_id)));
      select.value=scans.some(scan=>scan.scan_id===prior)?prior:'';
    } catch (error) {
      select.replaceChildren(new Option('Scan data unavailable',''));
    }
  }

  state.wbInspectorViews = { request: 'pretty', response: 'pretty' };
  state.wbRepeaterTab = 'request';
  state.wbRepeaterLastResponse = '';
  state.wbEndpointsCache = [];
  state.wbExchangesCache = [];

  async function loadDashboard() {
    try {
      const [data, scans] = await Promise.all([apiGet('/api/vf/dashboard'), apiGet('/api/vf/scans')]);
      const metric = (name, value) => {
        document.querySelectorAll(`[data-metric="${name}"]`).forEach((node) => {
          node.textContent = String(value ?? '—');
        });
      };
      metric('scans', data.scan_count);
      metric('verified', data.verified_count);
      metric('targets', data.target_count);
      metric('hosts', data.host_count);
      metric('endpoints', data.endpoint_count);
      metric('parameters', data.parameter_count);
      metric('requests', data.request_count);
      metric('responses', data.response_count);
      metric('tests', data.test_count);
      metric('evidence', data.evidence_count);
      state.savedScans = Array.isArray(scans) ? scans : [];
      renderWorkbenchRecentScans(state.savedScans);
      const select = byId('workbench-scan-select');
      if (select) {
        const previous = state.workbenchScanId;
        select.replaceChildren();
        if (!state.savedScans.length) select.append(new Option('No saved scans', ''));
        state.savedScans.forEach((scan) => {
          select.append(new Option(`${scan.target || 'Unknown target'} · ${scan.status || 'unknown'} · ${scan.scan_id}`, scan.scan_id));
        });
        state.workbenchScanId = state.savedScans.some((scan) => scan.scan_id === previous)
          ? previous
          : (state.savedScans[0]?.scan_id || '');
        select.value = state.workbenchScanId;
      }
      if (state.workbenchScanId) await loadWorkbenchScan(state.workbenchScanId);
      else renderWorkbenchEmpty();
    } catch (error) {
      workbenchMessage('workbench-overview', `Could not load saved scan data: ${error.message}`);
      workbenchMessage('workbench-target-meta', 'Database unavailable');
      workbenchMessage('workbench-traffic-meta', 'Could not load recorded exchanges.');
    }
  }

  function workbenchMessage(id, message) {
    const node = byId(id);
    if (!node) return;
    if (node.tagName === 'PRE' || node.tagName === 'STRONG' || node.tagName === 'SPAN') {
      node.textContent = message;
      return;
    }
    if (node.tagName === 'TBODY') {
      tableMessage(node, 4, message);
      return;
    }
    node.replaceChildren();
    const text = document.createElement('p');
    text.className = 'muted';
    text.textContent = message;
    node.append(text);
  }

  function renderWorkbenchEmpty() {
    if (byId('workbench-target-root')) byId('workbench-target-root').textContent = 'No scan selected';
    if (byId('wb-card-target')) byId('wb-card-target').textContent = 'No target selected';
    if (byId('wb-card-status')) byId('wb-card-status').textContent = 'Idle';
    workbenchMessage('workbench-target-meta', 'No saved scans in the configured SQLite database.');
    workbenchMessage('workbench-endpoints', 'No endpoint records are stored.');
    workbenchMessage('workbench-traffic-meta', '0 exchanges');
    tableMessage(byId('workbench-traffic-body'), 9, 'No recorded exchanges in this database.');
    workbenchMessage('workbench-request-view', 'Select a recorded exchange.');
    workbenchMessage('workbench-response-view', 'Select a recorded exchange.');
    workbenchMessage('workbench-request-meta', 'No request selected.');
    workbenchMessage('workbench-response-meta', 'Stored response · redacted by default.');
    workbenchMessage('workbench-overview', 'No saved scan selected.');
    renderWorkbenchSeverity([]);
    tableMessage(byId('workbench-top-vulns-body'), 4, 'No findings recorded');
    tableMessage(byId('workbench-findings'), 4, 'No findings recorded');
    workbenchMessage('workbench-events', 'No scan events are stored.');
    if (byId('workbench-endpoint-count')) byId('workbench-endpoint-count').textContent = '0';
  }

  async function loadWorkbenchScan(scanId) {
    if (!scanId) { renderWorkbenchEmpty(); return; }
    state.workbenchScanId = scanId;
    const params = new URLSearchParams({ scan_id: scanId, limit: '1000' });
    const [reportResult, endpointsResult, trafficResult, findingsResult, eventsResult, techResult] = await Promise.allSettled([
      apiGet(`/api/vf/scans/${encodeURIComponent(scanId)}`),
      apiGet(`/api/vf/endpoints?${params}`),
      apiGet(`/api/vf/scans/${encodeURIComponent(scanId)}/traffic?limit=50&offset=0`),
      apiGet(`/api/vf/findings?${params}`),
      apiGet(`/api/vf/scans/${encodeURIComponent(scanId)}/event-log?after=0&limit=1000`),
      apiGet(`/api/vf/technologies?${params}`)
    ]);
    const report = reportResult.status === 'fulfilled' ? reportResult.value : {};
    const scan = report.scan || state.savedScans.find((item) => item.scan_id === scanId) || {};
    const statistics = report.statistics || {};
    const endpoints = endpointsResult.status === 'fulfilled' ? (endpointsResult.value || []) : [];
    const exchanges = trafficResult.status === 'fulfilled' ? (trafficResult.value.items || []) : [];
    const findings = findingsResult.status === 'fulfilled' ? (findingsResult.value || []) : [];
    const events = eventsResult.status === 'fulfilled' ? (eventsResult.value.items || []) : [];
    const technologies = techResult.status === 'fulfilled' ? (techResult.value || []) : [];
    const parametersCount = Array.isArray(report.parameters)
      ? report.parameters.length
      : (statistics.parameters_discovered ?? 0);

    state.wbEndpointsCache = endpoints;
    state.wbExchangesCache = exchanges;
    state.workbenchExchanges = exchanges;
    state.selectedExchange = null;

    if (byId('workbench-target-root')) {
      byId('workbench-target-root').textContent = scan.target || 'Target unavailable';
    }
    if (byId('workbench-endpoint-count')) {
      byId('workbench-endpoint-count').textContent = String(endpoints.length);
    }

    renderWorkbenchSitemap(scanId, endpoints, byId('workbench-target-search')?.value || '');
    renderWorkbenchTraffic(exchanges, byId('workbench-history-filter')?.value || '');
    renderWorkbenchOverview(scan, statistics, report, exchanges.length, endpoints.length, findings.length, parametersCount, technologies);
    renderWorkbenchFindings(findings);
    renderWorkbenchSeverity(findings);
    renderWorkbenchEvents(events, scan.status || report.status);
  }

  function renderWorkbenchSitemap(scanId, endpoints, filterText = '') {
    const endpointBox = byId('workbench-endpoints');
    if (!endpointBox) return;
    endpointBox.replaceChildren();
    const query = String(filterText || '').trim().toLowerCase();
    const filtered = query
      ? endpoints.filter((ep) => `${ep.method || ''} ${ep.path || ''} ${ep.url || ''}`.toLowerCase().includes(query))
      : endpoints;
    if (!filtered.length) {
      workbenchMessage('workbench-endpoints', query ? 'No routes match filter.' : 'No endpoint records stored for this scan.');
      return;
    }
    const groups = new Map();
    filtered.slice(0, 45).forEach((ep) => {
      let rawPath = ep.path || '';
      if (!rawPath && ep.url) {
        try { rawPath = new URL(ep.url).pathname || '/'; } catch { rawPath = ep.url; }
      }
      const parts = String(rawPath || '/').split('/').filter(Boolean);
      const folder = parts.length > 1 ? `/${parts[0]}` : '/';
      if (!groups.has(folder)) groups.set(folder, []);
      groups.get(folder).push({ ...ep, displayPath: rawPath || '/' });
    });
    groups.forEach((items, folder) => {
      const folderEl = document.createElement('div');
      folderEl.className = 'site-map-folder';
      folderEl.textContent = `▾ 📁 ${folder}`;
      endpointBox.append(folderEl);
      items.forEach((endpoint) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'site-map-item';
        const method = document.createElement('span');
        method.className = 'site-map-method';
        method.dataset.method = String(endpoint.method || 'GET').toUpperCase();
        method.textContent = endpoint.method || 'GET';
        const path = document.createElement('span');
        path.className = 'site-map-path';
        path.textContent = endpoint.displayPath;
        const status = document.createElement('span');
        status.className = 'site-map-status';
        const code = Number(endpoint.status || 0);
        status.textContent = code > 0 ? String(code) : '—';
        if (code > 0) status.dataset.status = String(code);
        button.append(method, path, status);
        button.title = `${endpoint.method || 'GET'} ${endpoint.url || endpoint.displayPath}`;
        button.addEventListener('click', () => {
          const match = state.wbExchangesCache.find((ex) => String(ex.url || '').includes(endpoint.displayPath));
          if (match) {
            const row = byId('workbench-traffic-body')?.querySelector(`tr[data-exchange-id="${CSS.escape(match.exchange_id)}"]`);
            if (row) row.click();
            else loadWorkbenchExchange(match.exchange_id);
          } else {
            openWorkbenchEndpoint(scanId, endpoint);
          }
        });
        endpointBox.append(button);
      });
    });
  }

  async function openWorkbenchEndpoint(scanId, endpoint) {
    state.trafficScanId = scanId;
    navigate('endpoints');
    await populateScanSelect('endpoints-scan-filter');
    byId('endpoints-scan-filter').value = scanId;
    byId('endpoints-search').value = endpoint.path || endpoint.url || '';
    await loadEndpointsPage();
  }

  function renderWorkbenchTraffic(items, filterText = '') {
    const body = byId('workbench-traffic-body');
    if (!body) return;
    body.replaceChildren();
    const query = String(filterText || '').trim().toLowerCase();
    const filtered = query
      ? items.filter((item) => `${item.method || ''} ${item.url || ''} ${item.status || ''} ${item.module || ''}`.toLowerCase().includes(query))
      : items;
    if (byId('workbench-traffic-meta')) {
      byId('workbench-traffic-meta').textContent = `${filtered.length} of ${items.length} exchange(s)`;
    }
    if (!filtered.length) {
      tableMessage(body, 9, query ? 'No recorded HTTP exchanges match filter.' : 'No HTTP exchanges were recorded for this scan.');
      return;
    }
    filtered.forEach((item, index) => {
      const row = document.createElement('tr');
      row.dataset.exchangeId = String(item.exchange_id || '');
      let host = '—';
      let pathWithQuery = item.url || '—';
      let hasParams = Number(item.request_bytes || 0) > 0;
      try {
        const parsed = new URL(String(item.url || ''));
        host = parsed.host;
        pathWithQuery = `${parsed.pathname || '/'}${parsed.search || ''}`;
        if (parsed.search && parsed.search.length > 1) hasParams = true;
      } catch { /* keep raw URL fallback */ }
      const statusText = item.status == null ? '—' : String(item.status);
      const lengthText = String(item.response_bytes ?? 0);
      const moduleText = item.module || 'scanner';
      const titleText = item.error ? `Error: ${item.error}` : `${moduleText} · ${Number(item.duration_ms || 0).toFixed(0)} ms`;

      appendCell(row, String(index + 1));
      appendCell(row, host);
      const methodCell = document.createElement('td');
      const chip = document.createElement('span');
      chip.className = 'method-chip';
      chip.textContent = String(item.method || 'GET');
      methodCell.append(chip);
      row.append(methodCell);
      appendCell(row, pathWithQuery, 'workbench-url');
      const paramCell = document.createElement('td');
      const paramBadge = document.createElement('span');
      paramBadge.className = hasParams ? 'param-check' : 'param-none';
      paramBadge.textContent = hasParams ? '✓' : '·';
      paramCell.append(paramBadge);
      row.append(paramCell);
      const statusCell = appendCell(row, statusText, 'status-code');
      statusCell.dataset.status = statusText;
      appendCell(row, lengthText);
      appendCell(row, moduleText);
      appendCell(row, titleText);

      row.addEventListener('click', () => {
        body.querySelectorAll('tr[data-exchange-id]').forEach((r) => r.classList.remove('is-selected'));
        row.classList.add('is-selected');
        loadWorkbenchExchange(item.exchange_id);
      });
      body.append(row);
    });
    const firstRow = body.querySelector('tr[data-exchange-id]');
    if (firstRow) {
      firstRow.classList.add('is-selected');
      loadWorkbenchExchange(filtered[0].exchange_id);
    }
  }

  function formatNumberedLines(text) {
    const raw = String(text || '');
    return raw.split('\n').map((line, idx) => `${String(idx + 1).padStart(2, ' ')}  ${line}`).join('\n');
  }

  function formatHexDump(text) {
    const bytes = new TextEncoder().encode(String(text || '').slice(0, 2048));
    if (!bytes.length) return '00000000  [empty message]';
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const slice = bytes.slice(offset, offset + 16);
      const hex = Array.from(slice).map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
      const ascii = Array.from(slice).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
    }
    return lines.join('\n');
  }

  function renderWorkbenchCodePane(side) {
    const exchange = state.selectedExchange;
    const output = byId(side === 'request' ? 'workbench-request-view' : 'workbench-response-view');
    if (!output) return;
    if (!exchange) {
      output.textContent = `Select an exchange above to inspect the ${side}.`;
      return;
    }
    const mode = state.wbInspectorViews[side] || 'pretty';
    const baseText = side === 'request' ? renderRequest(exchange) : renderResponse(exchange);
    const renderer = window.VulnForgeTrafficInspector;
    let content = baseText;
    if (mode === 'hex') {
      content = formatHexDump(baseText);
    } else if (mode === 'headers' && renderer) {
      content = renderer.render(exchange, side, 'headers', side === 'request' ? renderRequest : renderResponse);
    } else if (mode === 'pretty') {
      content = formatNumberedLines(baseText);
    }
    output.textContent = content;
    document.querySelectorAll(`[data-wb-side="${side}"][data-wb-view]`).forEach((tab) => {
      tab.classList.toggle('is-active', tab.dataset.wbView === mode);
    });
  }

  function populateWorkbenchInspector(exchange) {
    const fillKv = (boxId, countId, pairs) => {
      const box = byId(boxId);
      const badge = byId(countId);
      if (badge) badge.textContent = String(pairs.length);
      if (!box) return;
      box.replaceChildren();
      if (!pairs.length) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'None recorded';
        box.append(empty);
        return;
      }
      pairs.forEach(([k, v]) => {
        const row = document.createElement('div');
        row.className = 'kv-row';
        const key = document.createElement('b');
        key.textContent = String(k);
        const val = document.createElement('span');
        val.textContent = String(v ?? '');
        row.append(key, val);
        box.append(row);
      });
    };
    if (!exchange) {
      ['attrs', 'reqheaders', 'respheaders', 'cookies', 'params'].forEach((k) => fillKv(`wb-list-${k}`, `wb-count-${k}`, []));
      return;
    }
    let path = exchange.url || '/';
    const queryPairs = [];
    try {
      const u = new URL(String(exchange.url || ''));
      path = `${u.pathname || '/'}${u.search || ''}`;
      u.searchParams.forEach((v, k) => queryPairs.push([`query:${k}`, v]));
    } catch { /* fallback */ }
    if (exchange.request_body) {
      try {
        const parsedBody = JSON.parse(exchange.request_body);
        if (parsedBody && typeof parsedBody === 'object') {
          Object.entries(parsedBody).forEach(([k, v]) => queryPairs.push([`json:${k}`, typeof v === 'object' ? JSON.stringify(v) : String(v)]));
        }
      } catch {
        queryPairs.push(['body', `${String(exchange.request_body).length} chars`]);
      }
    }
    const reqHeaders = Array.isArray(exchange.request_header_items) && exchange.request_header_items.length
      ? exchange.request_header_items
      : Object.entries(exchange.request_headers || {});
    const respHeaders = Array.isArray(exchange.response_header_items) && exchange.response_header_items.length
      ? exchange.response_header_items
      : Object.entries(exchange.response_headers || {});
    const cookiePairs = [];
    reqHeaders.forEach(([k, v]) => {
      if (String(k).toLowerCase() === 'cookie') cookiePairs.push(['Request Cookie', v]);
    });
    respHeaders.forEach(([k, v]) => {
      if (String(k).toLowerCase() === 'set-cookie') cookiePairs.push(['Set-Cookie', v]);
    });
    const attrs = [
      ['Method', exchange.method || 'GET'],
      ['Path', path],
      ['Status', exchange.status ?? 'No response'],
      ['Module', exchange.module || 'scanner'],
      ['Duration', `${Number(exchange.duration_ms || 0).toFixed(1)} ms`],
      ['Exchange ID', exchange.exchange_id || '—']
    ];
    fillKv('wb-list-attrs', 'wb-count-attrs', attrs);
    fillKv('wb-list-reqheaders', 'wb-count-reqheaders', reqHeaders);
    fillKv('wb-list-respheaders', 'wb-count-respheaders', respHeaders);
    fillKv('wb-list-cookies', 'wb-count-cookies', cookiePairs);
    fillKv('wb-list-params', 'wb-count-params', queryPairs);
  }

  function syncWorkbenchMiniRepeater(exchange) {
    if (!exchange) return;
    if (byId('wb-rep-method')) byId('wb-rep-method').textContent = exchange.method || 'GET';
    let path = exchange.url || '/';
    try {
      const u = new URL(String(exchange.url || ''));
      path = `${u.pathname || '/'}${u.search || ''}`;
    } catch { /* fallback */ }
    if (byId('wb-rep-path')) byId('wb-rep-path').value = path;
    state.wbRepeaterLastResponse = renderResponse(exchange);
    renderWorkbenchMiniRepeaterPane();
  }

  function renderWorkbenchMiniRepeaterPane() {
    const preview = byId('wb-rep-preview');
    if (!preview) return;
    if (!state.selectedExchange) {
      preview.textContent = 'Select an exchange above to stage in Guarded Repeater.';
      return;
    }
    preview.textContent = state.wbRepeaterTab === 'response'
      ? (state.wbRepeaterLastResponse || renderResponse(state.selectedExchange))
      : renderRequest(state.selectedExchange);
    document.querySelectorAll('[data-wb-rep-tab]').forEach((btn) => {
      btn.classList.toggle('is-active', btn.dataset.wbRepTab === state.wbRepeaterTab);
    });
  }

  async function sendWorkbenchMiniRepeater() {
    if (!state.selectedExchange) return;
    const authBox = byId('wb-rep-authorized');
    if (!authBox?.checked) {
      state.wbRepeaterTab = 'response';
      state.wbRepeaterLastResponse = 'Confirm authorization ("Authorized" checkbox) before sending a guarded replay request, or open Full Repeater.';
      renderWorkbenchMiniRepeaterPane();
      return;
    }
    const button = byId('wb-rep-send');
    if (button) { button.disabled = true; button.textContent = 'Sending…'; }
    try {
      const response = await fetch('/api/vf/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          source_exchange_id: state.selectedExchange.exchange_id,
          raw_request: renderRequest(state.selectedExchange),
          authorized: true,
          state_change_authorized: false
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
      state.wbRepeaterTab = 'response';
      state.wbRepeaterLastResponse = renderResponse(data.exchange || data);
      renderWorkbenchMiniRepeaterPane();
    } catch (error) {
      state.wbRepeaterTab = 'response';
      state.wbRepeaterLastResponse = `Guarded Repeater blocked or failed: ${error.message}`;
      renderWorkbenchMiniRepeaterPane();
    } finally {
      if (button) { button.disabled = false; button.textContent = 'Send'; }
    }
  }

  async function loadWorkbenchExchange(exchangeId) {
    if (!exchangeId) return;
    workbenchMessage('workbench-request-view', 'Loading stored request…');
    workbenchMessage('workbench-response-view', 'Loading stored response…');
    try {
      const exchange = await apiGet(`/api/vf/traffic/${encodeURIComponent(exchangeId)}`);
      state.selectedExchange = exchange;
      state.trafficExchangeId = exchangeId;
      renderWorkbenchCodePane('request');
      renderWorkbenchCodePane('response');
      populateWorkbenchInspector(exchange);
      syncWorkbenchMiniRepeater(exchange);
      const redaction = exchange.sensitive_values_stored ? 'plaintext opt-in' : 'redacted';
      byId('workbench-request-meta').textContent = `${exchange.method || 'HTTP'} · ${exchange.module || 'scan'} · ${redaction}`;
      const duration = Number(exchange.duration_ms);
      byId('workbench-response-meta').textContent = `HTTP ${exchange.status || '—'}${Number.isFinite(duration) && duration > 0 ? ` · ${duration.toFixed(1)} ms` : ''} · ${redaction}`;
    } catch (error) {
      workbenchMessage('workbench-request-view', `Could not load request: ${error.message}`);
      workbenchMessage('workbench-response-view', `Could not load response: ${error.message}`);
    }
  }

  function renderWorkbenchOverview(scan, statistics, report, exchangeCount, endpointCount, findingCount, parametersCount, technologies) {
    if (byId('wb-card-target')) byId('wb-card-target').textContent = scan.target || '—';
    const statusText = scan.status || report.status || 'unknown';
    if (byId('wb-card-status')) byId('wb-card-status').textContent = statusText;
    if (byId('workbench-target-meta')) {
      byId('workbench-target-meta').textContent = `Scan ID: ${scan.scan_id || state.workbenchScanId} · Profile: ${scan.test_profile || scan.profile || '—'}`;
    }
    if (byId('workbench-overview')) {
      const dur = scan.duration_s != null ? `${Number(scan.duration_s).toFixed(1)}s` : '—';
      byId('workbench-overview').textContent = `Started: ${formatDate(scan.started_at)} · Duration: ${dur}`;
    }
    const techBox = byId('workbench-tech-pills');
    if (techBox) {
      techBox.replaceChildren();
      if (!technologies.length) {
        const span = document.createElement('span');
        span.className = 'tech-pill';
        span.textContent = 'Passive fingerprint only · 0 tags';
        techBox.append(span);
      } else {
        technologies.slice(0, 6).forEach((t) => {
          const pill = document.createElement('span');
          pill.className = 'tech-pill';
          pill.textContent = t.name || t.category || 'Tech';
          pill.title = `${t.category || ''} (${t.confidence || 'observed'})`;
          techBox.append(pill);
        });
      }
    }
    if (byId('wb-stat-endpoints')) byId('wb-stat-endpoints').textContent = String(statistics.endpoints_discovered ?? scan.endpoints_count ?? endpointCount);
    if (byId('wb-stat-params')) byId('wb-stat-params').textContent = String(parametersCount);
    if (byId('wb-stat-requests')) byId('wb-stat-requests').textContent = String(statistics.requests_sent ?? scan.requests_count ?? exchangeCount);
    if (byId('wb-stat-findings')) byId('wb-stat-findings').textContent = String(findingCount);
  }

  function makeSeverityBadge(severity) {
    const sev = String(severity || 'info').toLowerCase();
    const badge = document.createElement('span');
    badge.className = `sev-pill sev-pill-${['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'info'}`;
    badge.textContent = sev.toUpperCase();
    return badge;
  }

  function renderWorkbenchFindings(items) {
    const body = byId('workbench-findings');
    if (!body) return;
    body.replaceChildren();
    if (!items.length) {
      tableMessage(body, 4, 'No findings recorded for this scan');
      return;
    }
    items.slice(0, 6).forEach((item, idx) => {
      const row = document.createElement('tr');
      appendCell(row, String(idx + 1));
      appendCell(row, `${item.title || item.category || 'Finding'} (${item.status || 'RECORD'})`);
      const sevCell = document.createElement('td');
      sevCell.append(makeSeverityBadge(item.severity));
      row.append(sevCell);
      let epText = item.endpoint || item.url || '—';
      try { epText = new URL(epText).pathname || epText; } catch { /* keep relative */ }
      appendCell(row, epText);
      row.addEventListener('click', () => navigate('findings'));
      body.append(row);
    });
  }

  function renderWorkbenchRecentScans(scans) {
    const body = byId('workbench-scans-body');
    if (!body) return;
    body.replaceChildren();
    if (!scans.length) {
      tableMessage(body, 4, 'No scans stored in SQLite');
      return;
    }
    scans.slice(0, 6).forEach((scan) => {
      const row = document.createElement('tr');
      appendCell(row, scan.target || scan.scan_id);
      const statusCell = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = 'burp-status-pill';
      pill.textContent = scan.status || 'completed';
      statusCell.append(pill);
      row.append(statusCell);
      const totalF = Number(scan.verified_count || 0) + Number(scan.candidates_count || 0);
      appendCell(row, `${totalF} (${scan.verified_count || 0}V)`);
      appendCell(row, `${scan.requests_count ?? 0} req`);
      row.addEventListener('click', () => {
        state.workbenchScanId = scan.scan_id;
        const select = byId('workbench-scan-select');
        if (select) select.value = scan.scan_id;
        loadWorkbenchScan(scan.scan_id);
      });
      body.append(row);
    });
  }

  function renderWorkbenchEvents(items, scanStatus = '') {
    const box = byId('workbench-events');
    if (byId('wb-console-badge')) {
      byId('wb-console-badge').textContent = scanStatus === 'running' ? '● Live Stream' : '● SQLite Event Log';
    }
    if (!box) return;
    box.replaceChildren();
    if (!items.length) {
      workbenchMessage('workbench-events', 'No persisted scan events are stored for this scan.');
      return;
    }
    items.slice(-10).forEach((item) => {
      const line = document.createElement('div');
      line.className = 'wb-console-line';
      const timeSpan = document.createElement('span');
      timeSpan.className = 'wb-console-time';
      const ts = Number(item.timestamp);
      const d = Number.isFinite(ts) ? new Date(ts * 1000) : new Date();
      timeSpan.textContent = `[${d.toTimeString().slice(0, 8)}]`;
      const msgSpan = document.createElement('span');
      msgSpan.textContent = `${item.kind || 'event'}: ${item.message || ''}`;
      line.append(timeSpan, msgSpan);
      box.append(line);
    });
  }

  function renderWorkbenchSeverity(items) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    items.forEach((item) => {
      const sev = String(item.severity || 'info').toLowerCase();
      if (Object.hasOwn(counts, sev)) counts[sev] += 1;
      else counts.info += 1;
    });
    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    if (byId('workbench-total-findings')) byId('workbench-total-findings').textContent = String(total);

    Object.entries(counts).forEach(([sev, count]) => {
      const node = document.querySelector(`[data-issue-count="${sev}"]`);
      if (node) node.textContent = String(count);
    });

    const colors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
      info: '#3b82f6'
    };
    const labels = {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      info: 'Info'
    };

    const segGroup = byId('workbench-donut-segments');
    if (segGroup) {
      segGroup.replaceChildren();
      const circumference = 2 * Math.PI * 44;
      let offset = 0;
      if (total > 0) {
        Object.entries(counts).forEach(([sev, count]) => {
          if (!count) return;
          const length = (count / total) * circumference;
          const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          circle.setAttribute('cx', '60');
          circle.setAttribute('cy', '60');
          circle.setAttribute('r', '44');
          circle.setAttribute('fill', 'none');
          circle.setAttribute('stroke', colors[sev]);
          circle.setAttribute('stroke-width', '14');
          circle.setAttribute('stroke-dasharray', `${length} ${circumference - length}`);
          circle.setAttribute('stroke-dashoffset', String(-offset));
          segGroup.append(circle);
          offset += length;
        });
      }
    }

    const legend = byId('workbench-severity');
    if (legend) {
      legend.replaceChildren();
      Object.entries(counts).forEach(([sev, count]) => {
        const pct = total > 0 ? `${((count / total) * 100).toFixed(1)}%` : '0.0%';
        const row = document.createElement('div');
        row.className = 'donut-legend-row';
        const dot = document.createElement('span');
        dot.className = 'donut-legend-dot';
        dot.style.background = colors[sev];
        const label = document.createElement('span');
        label.textContent = labels[sev];
        const val = document.createElement('b');
        val.textContent = `${count} (${pct})`;
        row.append(dot, label, val);
        legend.append(row);
      });
    }

    const topBody = byId('workbench-top-vulns-body');
    if (topBody) {
      topBody.replaceChildren();
      if (!items.length) {
        tableMessage(topBody, 4, 'No findings recorded for this scan');
        return;
      }
      const grouped = new Map();
      items.forEach((item) => {
        const key = item.title || item.category || 'Finding';
        const prev = grouped.get(key) || { title: key, severity: item.severity || 'info', count: 0 };
        prev.count += 1;
        grouped.set(key, prev);
      });
      Array.from(grouped.values()).sort((a, b) => b.count - a.count).slice(0, 5).forEach((entry, idx) => {
        const row = document.createElement('tr');
        appendCell(row, String(idx + 1));
        appendCell(row, entry.title);
        const sevCell = document.createElement('td');
        sevCell.append(makeSeverityBadge(entry.severity));
        row.append(sevCell);
        appendCell(row, String(entry.count));
        row.addEventListener('click', () => navigate('findings'));
        topBody.append(row);
      });
    }
  }

  function renderCompactScans(box,scans) {
    if(!box)return;box.replaceChildren();
    if(!scans.length){box.textContent='No saved scans in the selected database.';return;}
    scans.forEach(scan=>{const line=document.createElement('button');line.type='button';line.className='compact-data-row compact-data-button';
      line.textContent=`${scan.status} · ${scan.target} · ${scan.requests_count} request(s)`;
      line.addEventListener('click',()=>loadScanDetail(scan.scan_id));box.append(line);});
  }

  function renderCompactFindings(box,items) {
    if(!box)return;box.replaceChildren();
    if(!items.length){box.textContent='No finding records are stored.';return;}
    items.forEach(item=>{const line=document.createElement('div');line.className='compact-data-row';
      line.textContent=`${item.status} · ${String(item.severity||'info').toUpperCase()} · ${item.title}`;box.append(line);});
  }

  async function loadScansPage() {
    const body=byId('scans-table-body');tableMessage(body,9,'Loading stored scan history…');
    try {
      const scans=await apiGet('/api/vf/scans');state.savedScans=scans;body.replaceChildren();
      if(!scans.length)tableMessage(body,9,'No scans are stored in the configured structured database.');
      else scans.forEach(scan=>{const row=document.createElement('tr');
        appendCell(row,scan.scan_id);appendCell(row,scan.target,'traffic-url-cell');appendCell(row,scan.profile);
        appendCell(row,scan.status,'status-pill');appendCell(row,scan.endpoints_count);appendCell(row,`${scan.verified_count} verified / ${scan.candidates_count} candidate`);
        appendCell(row,scan.requests_count);appendCell(row,formatDate(scan.started_at));scanActionCell(row,scan);body.append(row);});
    } catch(error){tableMessage(body,9,`Could not load structured scan history: ${error.message}`);}
  }

  async function loadScanDetail(scanId) {
    const panel=byId('scan-detail-panel');if(!panel)return;
    if(state.activeRoute!=='scans') navigate('scans');
    panel.hidden=false;byId('scan-detail-title').textContent=`Scan ${scanId}`;byId('scan-detail-meta').textContent='Loading stored report summary…';byId('scan-detail-coverage').replaceChildren();
    state.selectedScanId=scanId;
    try {
      const report=await apiGet(`/api/vf/scans/${encodeURIComponent(scanId)}`);
      const scan=report.scan||{};const stats=report.statistics||{};
      byId('scan-detail-meta').textContent=`${scan.target||'Target unavailable'} · ${report.status||scan.status||'status unavailable'}`;
      const grid=byId('scan-detail-content');grid.replaceChildren();
      const pairs=[['Profile',scan.profile],['Testing portfolio',scan.test_profile],['Started',formatDate(scan.started_at)],
        ['Duration (seconds)',scan.duration_s],['Requests sent',stats.requests_sent],['Endpoints',stats.endpoints_discovered],
        ['Verified findings',stats.verified_findings_total],['Candidates',stats.candidates_total],['Status',report.status||scan.status],
        ['Stop reason',scan.stop_reason||'—']];
      pairs.forEach(([label,value])=>{const card=document.createElement('div');card.className='detail-item';const k=document.createElement('span');k.textContent=label;const v=document.createElement('strong');v.textContent=(value===undefined||value===null||value==='')?'—':String(value);card.append(k,v);grid.append(card);});
      const coverageBox=byId('scan-detail-coverage');coverageBox.replaceChildren();const coverage=Array.isArray(report.coverage)?report.coverage:[];
      if(!coverage.length){coverageBox.textContent='No coverage matrix is stored in this report.';}
      else coverage.forEach(item=>{const card=document.createElement('article');card.className='coverage-item';const head=document.createElement('div');head.className='coverage-item-heading';const title=document.createElement('strong');title.textContent=item.category||'Uncategorized check';const badge=document.createElement('span');const coverageClass=String(item.status||'UNKNOWN').toLowerCase().replace(/[^a-z0-9_-]/g,'');badge.className=`coverage-status coverage-${coverageClass||'unknown'}`;badge.textContent=item.status||'UNKNOWN';head.append(title,badge);const note=document.createElement('p');note.textContent=item.notes||'No limitation note stored.';card.append(head,note);coverageBox.append(card);});
    } catch(error){byId('scan-detail-meta').textContent=`Could not load scan details: ${error.message}`;byId('scan-detail-content').replaceChildren();byId('scan-detail-coverage').textContent='Coverage could not be loaded.';}
  }

  async function loadTargetsPage() {
    const body=byId('targets-table-body');tableMessage(body,4,'Loading targets…');
    try{const rows=await apiGet('/api/vf/targets');body.replaceChildren();if(!rows.length){tableMessage(body,4,'No targets are stored.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');appendCell(row,item.target,'traffic-url-cell');appendCell(row,item.scan_count);appendCell(row,item.status);appendCell(row,formatDate(item.last_scan));body.append(row);});
    }catch(error){tableMessage(body,4,`Could not load targets: ${error.message}`);}
  }

  async function loadEndpointsPage() {
    const body=byId('endpoints-table-body');tableMessage(body,7,'Loading endpoint records…');
    await populateScanSelect('endpoints-scan-filter');
    try{const q=new URLSearchParams();const scan=byId('endpoints-scan-filter').value;const search=byId('endpoints-search').value.trim();if(scan)q.set('scan_id',scan);if(search)q.set('search',search);q.set('limit','1000');
      const rows=await apiGet(`/api/vf/endpoints?${q}`);body.replaceChildren();if(!rows.length){tableMessage(body,7,'No endpoints match these filters.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');appendCell(row,item.scan_id);appendCell(row,item.method);appendCell(row,item.url,'traffic-url-cell');const code=Number(item.status);const statusCell=appendCell(row,Number.isFinite(code)&&code>0?`HTTP ${code}`:'Not recorded');if(!(Number.isFinite(code)&&code>0))statusCell.title='No HTTP response status is stored for this inventory entry; this does not establish that the endpoint is unavailable.';appendCell(row,item.source);appendCell(row,item.content_type);appendCell(row,item.state_changing?'Yes':'No');body.append(row);});
    }catch(error){tableMessage(body,7,`Could not load endpoints: ${error.message}`);}
  }

  async function loadParametersPage() {
    const body=byId('parameters-table-body'),select=byId('parameters-scan-select');
    tableMessage(body,6,'Loading stored parameters…');
    try{
      const scans=await apiGet('/api/vf/scans');select.replaceChildren();
      if(!scans.length){select.append(new Option('No saved scans',''));tableMessage(body,6,'No scan is available.');return;}
      scans.forEach(scan=>select.append(new Option(`${scan.target||'Unknown target'} · ${scan.scan_id}`,scan.scan_id)));
      const selected=scans.some(scan=>scan.scan_id===state.parameterScanId)?state.parameterScanId:
        (scans.some(scan=>scan.scan_id===state.activeScanId)?state.activeScanId:scans[0].scan_id);
      state.parameterScanId=selected;select.value=selected;
      const q=new URLSearchParams({limit:'1000'}),search=byId('parameters-search').value.trim();if(search)q.set('search',search);
      const result=await apiGet(`/api/vf/scans/${encodeURIComponent(selected)}/objects/parameters?${q}`);
      state.parameterItems=Array.isArray(result.items)?result.items:[];
      const location=byId('parameters-location-filter').value;
      const rows=state.parameterItems.filter(item=>!location||String(item.location||'').toLowerCase()===location);
      body.replaceChildren();if(!rows.length){tableMessage(body,6,'No stored parameters match this scan/filter.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');appendCell(row,item.name);appendCell(row,item.location);appendCell(row,item.method);appendCell(row,item.endpoint,'traffic-url-cell');appendCell(row,item.type_hint);appendCell(row,item.source);
        row.tabIndex=0;row.setAttribute('role','button');const selectRow=()=>{byId('parameter-detail').textContent=JSON.stringify(item,null,2);};row.addEventListener('click',selectRow);row.addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();selectRow();}});body.append(row);});
    }catch(error){tableMessage(body,6,`Could not load stored parameters: ${error.message}`);}
  }

  function renderResearchRows() {
    const body=byId('research-table-body'),query=byId('research-search').value.trim().toLowerCase();
    const rows=state.researchItems.filter(item=>!query||JSON.stringify(item).toLowerCase().includes(query));
    body.replaceChildren();
    if(!rows.length){tableMessage(body,3,query?'No stored objects match this search.':'No records of this type are stored for the scan.');return;}
    rows.forEach((item,index)=>{
      const row=document.createElement('tr');row.tabIndex=0;row.setAttribute('role','button');
      const identity=item.hypothesis_id||item.test_id||item.evidence_id||item.asset_id||item.resource_id||item.actor_id||item.application_id||item.field_path||item.operation_id||item.url||item.endpoint||item.id||`record ${index+1}`;
      const status=item.status||item.state||item.type||item.category||item.asset_type||item.object_type||'stored record';
      const summary=item.reason||item.summary||item.title||item.description||item.url||item.endpoint||item.message||item.name||item.field_path||'Open structured record';
      appendCell(row,identity);appendCell(row,status);appendCell(row,summary);
      const select=()=>{byId('research-detail').textContent=JSON.stringify(item,null,2);};
      row.addEventListener('click',select);row.addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();select();}});body.append(row);
    });
  }

  async function loadResearchPage(reset=true) {
    const select=byId('research-scan-select'),kind=byId('research-kind-select').value;
    const body=byId('research-table-body');if(reset){state.researchOffset=0;state.researchItems=[];state.researchHasMore=false;byId('research-more').hidden=true;tableMessage(body,3,'Loading stored research records…');}
    try{
      const scans=await apiGet('/api/vf/scans');select.replaceChildren();
      if(!scans.length){select.append(new Option('No saved scans',''));state.researchItems=[];tableMessage(body,3,'No scan is available.');return;}
      scans.forEach(scan=>select.append(new Option(`${scan.target||'Unknown target'} · ${scan.scan_id}`,scan.scan_id)));
      const selected=scans.some(scan=>scan.scan_id===state.researchScanId)?state.researchScanId:
        (scans.some(scan=>scan.scan_id===state.activeScanId)?state.activeScanId:scans[0].scan_id);
      state.researchScanId=selected;select.value=selected;
      const q=new URLSearchParams({limit:'500',offset:String(state.researchOffset)}),search=byId('research-search').value.trim();if(search)q.set('search',search);
      const result=await apiGet(`/api/vf/scans/${encodeURIComponent(selected)}/objects/${encodeURIComponent(kind)}?${q}`);
      const items=Array.isArray(result.items)?result.items:[];state.researchItems=reset?items:state.researchItems.concat(items);
      state.researchOffset=Number(result.offset||0)+items.length;state.researchHasMore=Boolean(result.has_more);byId('research-more').hidden=!state.researchHasMore;
      byId('research-summary').textContent=`${state.researchItems.length} stored ${kind} record(s) loaded · scan ${selected}${state.researchHasMore?' · more records available':''}`;
      if(reset)byId('research-detail').textContent='Select a stored record to inspect its JSON.';
      renderResearchRows();
    }catch(error){state.researchItems=[];state.researchHasMore=false;byId('research-more').hidden=true;byId('research-summary').textContent=`Research data unavailable: ${error.message}`;tableMessage(body,3,`Could not load stored research objects: ${error.message}`);}
  }

  async function loadTechnologiesPage() {
    const body=byId('technologies-table-body');tableMessage(body,6,'Loading observed technologies…');
    try{const q=new URLSearchParams({limit:'1000'});const search=byId('technology-search').value.trim();if(search)q.set('search',search);
      const rows=await apiGet(`/api/vf/technologies?${q}`);body.replaceChildren();if(!rows.length){tableMessage(body,6,'No technology observations match this filter.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');appendCell(row,item.scan_id);appendCell(row,item.target,'traffic-url-cell');appendCell(row,item.name||'Name missing in stored record');appendCell(row,item.category||'Not recorded');appendCell(row,item.confidence||'Not recorded');
        const cell=document.createElement('td');cell.className='technology-evidence-cell';const samples=Array.isArray(item.signals)?item.signals.slice(0,8):[];const observed=Number(item.observations_count)||samples.length;
        if(!samples.length)cell.textContent='No evidence samples stored';else{const details=document.createElement('details');const summary=document.createElement('summary');const omitted=Number(item.evidence_samples_omitted)||0;summary.textContent=`${samples.length} evidence sample${samples.length===1?'':'s'}${omitted?` shown · ${omitted} more hidden`:''} · ${observed} match${observed===1?'':'es'}`;details.append(summary);const list=document.createElement('ul');samples.forEach(signal=>{const li=document.createElement('li');li.textContent=String(signal);list.append(li);});details.append(list);cell.append(details);}row.append(cell);body.append(row);});
    }catch(error){tableMessage(body,6,`Could not load technologies: ${error.message}`);}
  }

  async function loadFindingsPage(verifiedOnly=false) {
    const body=byId(verifiedOnly?'verified-table-body':'findings-table-body');const cols=verifiedOnly?6:7;tableMessage(body,cols,'Loading finding records…');
    try{const q=new URLSearchParams({limit:'1000'});if(verifiedOnly)q.set('status','VERIFIED');else{
      const status=byId('finding-status-filter').value,severity=byId('finding-severity-filter').value,search=byId('finding-search').value.trim();if(status)q.set('status',status);if(severity)q.set('severity',severity);if(search)q.set('search',search);}
      const rows=await apiGet(`/api/vf/findings?${q}`);body.replaceChildren();if(!rows.length){tableMessage(body,cols,verifiedOnly?'No VERIFIED findings are stored.':'No findings match these filters.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');if(verifiedOnly){appendCell(row,item.severity);appendCell(row,item.title);appendCell(row,item.endpoint||item.target,'traffic-url-cell');appendCell(row,item.parameter);appendCell(row,item.confidence);appendCell(row,item.scan_id);}else{
        appendCell(row,item.status,'status-pill');appendCell(row,item.severity);appendCell(row,item.title);appendCell(row,item.category);appendCell(row,item.endpoint||item.target,'traffic-url-cell');appendCell(row,item.parameter);appendCell(row,item.scan_id);}
        row.addEventListener('click',()=>{state.evidenceFindingId=item.finding_id||'';if(!verifiedOnly){loadFindingDetail(item.finding_id||'');byId('finding-detail-view')?.scrollIntoView({block:'nearest'});}else navigate('evidence');});body.append(row);});
    }catch(error){tableMessage(body,cols,`Could not load findings: ${error.message}`);}
  }

  async function loadFindingDetail(findingId) {
    const output = byId('finding-detail-view');
    if (!output || !findingId) return;
    output.textContent = 'Loading finding evidence chain…';
    try {
      const result = await apiGet(`/api/vf/findings/${encodeURIComponent(findingId)}`);
      output.textContent = JSON.stringify(result, null, 2);
    } catch (error) { output.textContent = `Could not load finding detail: ${error.message}`; }
  }

  async function loadEvidencePage() {
    const body=byId('evidence-table-body');tableMessage(body,5,'Loading evidence records…');await populateScanSelect('evidence-scan-filter');
    try{const q=new URLSearchParams({limit:'1000'});const scan=byId('evidence-scan-filter').value;if(scan)q.set('scan_id',scan);if(state.evidenceFindingId)q.set('finding_id',state.evidenceFindingId);
      const rows=await apiGet(`/api/vf/evidence?${q}`);body.replaceChildren();if(!rows.length){tableMessage(body,5,'No evidence records match this selection.');return;}
      rows.forEach(item=>{const row=document.createElement('tr');appendCell(row,item.evidence_id);appendCell(row,item.finding_id);appendCell(row,item.test_id);appendCell(row,item.target,'traffic-url-cell');const evidence=item.evidence||{};appendCell(row,evidence.summary||evidence.type||evidence.source||'Persisted evidence');
        row.addEventListener('click',()=>{byId('evidence-detail').textContent=JSON.stringify(item,null,2);});body.append(row);});
    }catch(error){tableMessage(body,5,`Could not load evidence: ${error.message}`);}
  }

  async function loadReportsPage() {
    const body=byId('reports-table-body');tableMessage(body,6,'Loading report inventory…');
    try{const rows=await apiGet('/api/vf/reports');body.replaceChildren();if(!rows.length){tableMessage(body,6,'No saved reports are available.');return;}
      rows.forEach(scan=>{const row=document.createElement('tr');appendCell(row,scan.scan_id);appendCell(row,scan.target,'traffic-url-cell');appendCell(row,scan.status);appendCell(row,`${scan.verified_count} verified / ${scan.candidates_count} candidate`);appendCell(row,formatDate(scan.started_at));const cell=document.createElement('td');
        cell.append(actionButton('Coverage',()=>loadScanDetail(scan.scan_id),'text-button'));
        if(scan.status==='running'){cell.append(document.createTextNode('Report will be available when the scan finishes.'));}else ['json','html','md','pdf','har'].forEach(fmt=>{const link=document.createElement('a');link.href=`/api/vf/scans/${encodeURIComponent(scan.scan_id)}/export/${fmt}`;link.textContent=fmt.toUpperCase();link.className='export-link';link.setAttribute('download','');cell.append(link);});row.append(cell);body.append(row);});
    }catch(error){tableMessage(body,6,`Could not load reports: ${error.message}`);}
  }

  function renderStoredEvents() {
    const body=byId('events-table-body');
    const query=byId('events-search').value.trim().toLowerCase();
    const rows=state.eventItems.filter(item=>!query||`${item.kind} ${item.message} ${JSON.stringify(item.data||{})}`.toLowerCase().includes(query));
    body.replaceChildren();
    if(!rows.length){tableMessage(body,4,query?'No persisted events match this search.':'No events are stored for this scan.');return;}
    rows.forEach(item=>{
      const row=document.createElement('tr');row.tabIndex=0;row.setAttribute('role','button');
      appendCell(row,item.event_id);appendCell(row,formatDate(item.timestamp));appendCell(row,item.kind);
      appendCell(row,item.message);
      const select=()=>{byId('event-detail').textContent=JSON.stringify(item,null,2);};
      row.addEventListener('click',select);row.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();select();}});
      body.append(row);
    });
  }

  async function loadEventsPage() {
    if(state.storedEventSource){state.storedEventSource.close();state.storedEventSource=null;}
    const select=byId('events-scan-select'),body=byId('events-table-body');
    state.eventItems=[];state.eventHasMore=false;state.eventNextCursor=0;byId('events-more').hidden=true;
    tableMessage(body,4,'Loading persisted scan events…');
    try {
      const scans=await apiGet('/api/vf/scans');
      select.replaceChildren();
      if(!scans.length){select.append(new Option('No saved scans',''));state.eventItems=[];byId('events-summary').textContent='No structured scans are stored.';tableMessage(body,4,'No scan selected.');return;}
      scans.forEach(scan=>select.append(new Option(`${scan.target||'Unknown target'} · ${scan.scan_id}`,scan.scan_id)));
      const selected=scans.some(scan=>scan.scan_id===state.eventScanId)?state.eventScanId:
        (scans.some(scan=>scan.scan_id===state.activeScanId)?state.activeScanId:scans[0].scan_id);
      const scan=scans.find(item=>item.scan_id===selected);
      state.eventScanId=selected;state.eventScanStatus=String(scan?.status||'').toLowerCase();select.value=selected;
      const result=await apiGet(`/api/vf/scans/${encodeURIComponent(selected)}/event-log?limit=1000`);
      state.eventItems=Array.isArray(result.items)?result.items:[];
      state.eventNextCursor=Number(result.next_after)||0;state.eventHasMore=Boolean(result.has_more);
      byId('events-more').hidden=!state.eventHasMore;
      byId('events-summary').textContent=`${state.eventItems.length} persisted event(s) loaded · scan ${selected}${state.eventHasMore?' · older events available':''}`;
      byId('event-detail').textContent='Select a stored event to inspect its structured JSON.';
      renderStoredEvents();
      if(state.eventScanStatus==='running'){
        const cursor=state.eventItems.reduce((max,item)=>Math.max(max,Number(item.event_id)||0),0);
        const stream=new EventSource(`/api/vf/scans/${encodeURIComponent(selected)}/events?after=${cursor}`);
        state.storedEventSource=stream;
        stream.onmessage=message=>{
          try{
            const item=JSON.parse(message.data);
            if(Number.isFinite(Number(item.event_id))&&!state.eventItems.some(existing=>existing.event_id===item.event_id)){
              state.eventItems.push(item);state.eventItems.sort((a,b)=>a.event_id-b.event_id);renderStoredEvents();
              byId('events-summary').textContent=`${state.eventItems.length} persisted event(s) · scan ${selected} · live updates connected`;
            }
            if(['scan-complete','scan-error','scan-stopped'].includes(item.kind)){stream.close();if(state.storedEventSource===stream)state.storedEventSource=null;state.eventScanStatus='completed';}
          }catch(error){byId('events-summary').textContent=`Received an unreadable event payload: ${error.message}`;}
        };
        stream.onerror=()=>{byId('events-summary').textContent=`${state.eventItems.length} persisted event(s) · live stream reconnecting or unavailable; Refresh reloads SQLite history.`;};
      }
    } catch(error) {
      state.eventItems=[];byId('events-summary').textContent=`Event history unavailable: ${error.message}`;
      tableMessage(body,4,`Could not load stored events: ${error.message}`);
    }
  }

  async function loadMoreEvents() {
    if(!state.eventScanId||!state.eventHasMore)return;
    const button=byId('events-more');button.disabled=true;
    try{
      const result=await apiGet(`/api/vf/scans/${encodeURIComponent(state.eventScanId)}/event-log?after=${state.eventNextCursor}&limit=1000`);
      const seen=new Set(state.eventItems.map(item=>item.event_id));
      for(const item of result.items||[])if(!seen.has(item.event_id))state.eventItems.push(item);
      state.eventItems.sort((a,b)=>a.event_id-b.event_id);
      state.eventNextCursor=Number(result.next_after)||state.eventNextCursor;state.eventHasMore=Boolean(result.has_more);
      byId('events-more').hidden=!state.eventHasMore;
      byId('events-summary').textContent=`${state.eventItems.length} persisted event(s) loaded · scan ${state.eventScanId}${state.eventHasMore?' · more older events available':''}`;
      renderStoredEvents();
    }catch(error){byId('events-summary').textContent=`Could not load the next event page: ${error.message}`;}
    finally{button.disabled=false;}
  }

  function appendConsoleLine(message, level = 'INFO', timestamp = '') {
    const output = byId('live-terminal-output');
    if (!output) return;
    const muted = output.querySelector('.console-muted');
    if (muted) muted.remove();
    const row = document.createElement('div');
    row.className = 'console-line';
    row.dataset.level = String(level || 'INFO').slice(0, 24);
    const prefix = timestamp ? `[${timestamp}] ` : '';
    row.textContent = `${prefix}${String(message ?? '')}`;
    output.appendChild(row);
    while (output.childElementCount > 800) output.firstElementChild.remove();
    output.scrollTop = output.scrollHeight;
  }

  function connectConsole(event) {
    event.preventDefault();
    const scanId = byId('console-scan-id').value.trim();
    if (!scanId) {
      appendConsoleLine('Enter a scan ID before connecting.', 'ERROR');
      return;
    }
    disconnectConsole(false);
    byId('live-terminal-output').replaceChildren();
    appendConsoleLine(`Connecting to scan ${scanId}…`, 'SYSTEM');
    const stream = new EventSource(`/api/vf/scans/${encodeURIComponent(scanId)}/events`);
    state.eventSource = stream;
    stream.onmessage = (eventMessage) => {
      try {
        const item = JSON.parse(eventMessage.data);
        appendConsoleLine(item.message, item.kind, item.timestamp);
        if (['scan-complete','scan-error','scan-stopped'].includes(item.kind)) {
          stream.close();
          state.eventSource = null;
        }
      } catch {
        appendConsoleLine('Received an unreadable event from the scan stream.', 'ERROR');
      }
    };
    stream.onerror = () => {
      if (state.eventSource === stream) appendConsoleLine('Stream interrupted or scan is no longer active.', 'ERROR');
    };
  }

  function disconnectConsole(showMessage = true) {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
      if (showMessage) appendConsoleLine('Disconnected from scan stream.', 'SYSTEM');
    }
  }

  async function loadRepeaterHistory() {
    const list = byId('repeater-history-list');
    if (!list) return;
    list.replaceChildren();
    const loading = document.createElement('p');
    loading.className = 'muted';
    loading.textContent = 'Loading request history…';
    list.append(loading);
    try {
      const response = await fetch('/api/vf/repeater/history', { headers: { Accept: 'application/json' } });
      const items = await response.json();
      if (!response.ok) throw new Error(items.detail || `Request failed (${response.status})`);
      state.repeaterHistory = Array.isArray(items) ? items : [];
      list.replaceChildren();
      if (!state.repeaterHistory.length) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'No saved Repeater requests.';
        list.append(empty);
        return;
      }
      state.repeaterHistory.forEach((item, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'history-item';
        button.dataset.index = String(index);
        const method = document.createElement('strong');
        method.textContent = String(item.method || 'HTTP');
        const url = document.createElement('span');
        url.textContent = String(item.url || '');
        button.append(method, url);
        button.addEventListener('click', async () => {
          try {
            const detailResponse = await fetch(`/api/vf/traffic/${encodeURIComponent(item.exchange_id)}`, { headers: { Accept: 'application/json' } });
            const exchange = await detailResponse.json();
            if (!detailResponse.ok) throw new Error(exchange.detail || `Request failed (${detailResponse.status})`);
            state.repeaterSourceExchangeId = exchange.exchange_id;
            byId('repeater-authorized').checked = false;
            byId('repeater-state-change').checked = false;
            byId('repeater-raw-request').value = renderRequest(exchange);
            byId('repeater-raw-response').textContent = renderResponse(exchange);
            byId('repeater-source-meta').textContent = `Source ${exchange.exchange_id} · ${exchange.scan_id || 'scan unavailable'} · original saved scope`;
            byId('repeater-status').textContent = exchange.status ? `HTTP ${exchange.status}` : 'Loaded';
          } catch (error) { byId('repeater-status').textContent = `Load failed: ${error.message}`; }
        });
        list.append(button);
      });
    } catch (error) {
      list.replaceChildren();
      const failure = document.createElement('p');
      failure.className = 'muted';
      failure.textContent = `Could not load Repeater history: ${error.message}`;
      list.append(failure);
    }
  }

  async function sendRepeaterRequest() {
    const button = byId('btn-repeater-send');
    const output = byId('repeater-raw-response');
    const requestText = byId('repeater-raw-request').value;
    const sourceExchangeId = state.repeaterSourceExchangeId;
    button.disabled = true;
    button.textContent = 'Sending…';
    byId('repeater-status').textContent = 'Sending';
    output.textContent = 'Waiting for response…';
    try {
      const response = await fetch('/api/vf/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ raw_request: requestText, source_exchange_id: sourceExchangeId,
          authorized: byId('repeater-authorized').checked,
          confirm_state_change: byId('repeater-state-change').checked })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
      output.textContent = renderResponse(result);
      byId('repeater-status').textContent = result.status ? `HTTP ${result.status}` : 'No response';
      state.repeaterSourceExchangeId = result.exchange_id || state.repeaterSourceExchangeId;
      byId('repeater-source-meta').textContent = `Follow-up ${result.exchange_id || ''} · parent ${result.parent_exchange_id || sourceExchangeId}`;
      await loadRepeaterHistory();
    } catch (error) {
      output.textContent = `Request error: ${error.message}`;
      byId('repeater-status').textContent = 'Error';
    } finally {
      byId('repeater-authorized').checked = false;
      byId('repeater-state-change').checked = false;
      button.disabled = false;
      button.textContent = 'Send guarded request';
    }
  }

  function appendScanEvent(event) {
    const output = byId('scan-live-feed');
    if (!output) return;
    const muted = output.querySelector('.console-muted');
    if (muted) muted.remove();
    const row = document.createElement('div');
    row.className = 'scan-event-line';
    row.dataset.kind = String(event.kind || 'event');
    const kind = document.createElement('span');
    kind.className = 'scan-event-kind';
    kind.textContent = String(event.kind || 'event').replaceAll('-', ' ');
    const message = document.createElement('span');
    const data = event.data && typeof event.data === 'object' ? event.data : {};
    let text = String(event.message || 'Scan event');
    if (event.kind === 'http-exchange') {
      const status = data.status ? ` · HTTP ${data.status}` : '';
      const module = data.module ? ` · ${data.module}` : '';
      text += `${status}${module}`;
      state.scanRequestCount += 1;
      byId('scan-live-requests').textContent = String(state.scanRequestCount);
    }
    message.textContent = text;
    row.append(kind, message);
    output.append(row);
    while (output.childElementCount > 500) output.firstElementChild.remove();
    output.scrollTop = output.scrollHeight;
  }

  async function startVfScan(event) {
    event.preventDefault();
    const form = byId('scan-start-form');
    const button = byId('scan-start-button');
    const errorBox = byId('scan-start-error');
    errorBox.hidden = true;
    let headers={},auth_data={},scope_policy={};
    const scopeText=byId('scan-scope-policy').value.trim();
    if(scopeText){
      try{scope_policy=JSON.parse(scopeText);if(!scope_policy||Array.isArray(scope_policy)||typeof scope_policy!=='object')throw new Error('Use a JSON object with scope policy fields.');}
      catch(error){errorBox.textContent=`Invalid scope policy JSON: ${error.message}`;errorBox.hidden=false;return;}
    }
    const headerText=byId('scan-extra-headers').value.trim();
    if(headerText){
      try{headers=JSON.parse(headerText);if(!headers||Array.isArray(headers)||typeof headers!=='object')throw new Error('Use a JSON object of header name/value pairs.');}
      catch(error){errorBox.textContent=`Invalid request headers JSON: ${error.message}`;errorBox.hidden=false;return;}
    }
    const authText=byId('scan-auth-config').value.trim();
    if(authText){
      try{auth_data=JSON.parse(authText);if(!auth_data||Array.isArray(auth_data)||typeof auth_data!=='object')throw new Error('Use the documented JSON object format.');}
      catch(error){errorBox.textContent=`Invalid authorization test JSON: ${error.message}`;errorBox.hidden=false;return;}
    }
    const payload = {
      target_url: byId('scan-target-url').value.trim(),
      authorized: byId('scan-authorized').checked,
      test_profile: byId('scan-priority').value,
      safety_mode: byId('scan-lab-mode').checked ? 'LAB' : byId('scan-safety-mode').value,
      lab_mode: byId('scan-lab-mode').checked,
      store_sensitive_http: byId('scan-store-sensitive').checked,
      headers,
      auth_data,
      scope_policy
    };
    button.disabled = true;
    button.textContent = 'Starting…';
    try {
      const response = await fetch('/api/vf/scans/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
      state.activeScanId = String(result.scan_id);
      state.trafficScanId = state.activeScanId;
      state.scanRequestCount = 0;
      byId('scan-live-id').textContent = state.activeScanId;
      byId('scan-live-target').textContent = String(result.target || payload.target_url);
      byId('scan-live-status').textContent = 'Running';
      byId('scan-live-requests').textContent = '0';
      byId('scan-live-error').hidden = true;
      byId('scan-live-feed').replaceChildren();
      if (state.eventSource) state.eventSource.close();
      navigate('scan-live');
      const stream = new EventSource(`/api/vf/scans/${encodeURIComponent(state.activeScanId)}/events`);
      state.eventSource = stream;
      stream.onmessage = (message) => {
        try {
          const item = JSON.parse(message.data);
          appendScanEvent(item);
          if (item.kind === 'scan-complete') {
            byId('scan-live-status').textContent = String(item.data?.status || 'completed');
            stream.close();
            if (state.eventSource === stream) state.eventSource = null;
          } else if (item.kind === 'scan-error') {
            byId('scan-live-status').textContent = 'failed';
            const box = byId('scan-live-error');
            box.textContent = String(item.data?.error || item.message || 'Scan failed.');
            box.hidden = false;
            stream.close();
            if (state.eventSource === stream) state.eventSource = null;
          }
        } catch {
          appendScanEvent({ kind: 'stream-warning', message: 'Received an unreadable scan event.' });
        }
      };
      stream.onerror = () => {
        if (state.eventSource === stream) {
          appendScanEvent({ kind: 'stream-warning', message: 'Live stream disconnected; refresh HTTP traffic to see exchanges already saved.' });
        }
      };
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.hidden = false;
    } finally {
      button.disabled = false;
      button.textContent = 'Start scan';
      if (!form.checkValidity()) form.reportValidity();
    }
  }

  function trafficMessage(message) {
    const body = byId('traffic-table-body');
    if (!body) return;
    body.replaceChildren();
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'table-empty';
    cell.textContent = message;
    row.append(cell);
    body.append(row);
    byId('traffic-summary').textContent = message;
  }

  async function refreshTrafficIfRunning() {
    if (state.activeRoute !== 'traffic' || !state.trafficScanId) return;
    try {
      const response = await fetch(`/api/vf/scans/${encodeURIComponent(state.trafficScanId)}/status`,
        { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('Status unavailable');
      const status = await response.json();
      if (status.status === 'running') await loadTrafficPage();
      else if (state.trafficRefreshTimer) {
        clearInterval(state.trafficRefreshTimer);
        state.trafficRefreshTimer = null;
      }
    } catch { /* keep the table usable if the status endpoint is temporarily unavailable */ }
  }

  async function loadTrafficScans() {
    const select = byId('traffic-scan-select');
    if (!select) return;
    select.disabled = true;
    select.replaceChildren(new Option('Loading scans…', ''));
    try {
      const response = await fetch('/api/vf/scans', { headers: { Accept: 'application/json' } });
      const scans = await response.json();
      if (!response.ok) throw new Error(scans.detail || `Request failed (${response.status})`);
      state.trafficScans = Array.isArray(scans) ? scans : [];
      select.replaceChildren();
      if (!state.trafficScans.length) {
        select.append(new Option('No saved scans', ''));
        state.trafficScanId = '';
        trafficMessage('No saved scans in the selected VULNFORGE database.');
        return;
      }
      state.trafficScans.forEach((scan) => {
        const label = `${scan.target || 'Unknown target'} · ${scan.scan_id} · ${scan.status || 'unknown'}`;
        select.append(new Option(label, scan.scan_id));
      });
      const selected = state.trafficScans.some((scan) => scan.scan_id === state.trafficScanId)
        ? state.trafficScanId : state.trafficScans[0].scan_id;
      state.trafficScanId = selected;
      select.value = selected;
      await loadTrafficPage(true);
    } catch (error) {
      select.replaceChildren(new Option('Scan database unavailable', ''));
      trafficMessage(`Could not load scan history: ${error.message}`);
    } finally {
      select.disabled = false;
    }
  }

  function trafficFilters() {
    const params = new URLSearchParams();
    const method = byId('traffic-method-filter').value;
    const endpoint = byId('traffic-search-filter').value.trim();
    const statusText = byId('traffic-status-filter').value.trim();
    const module = byId('traffic-module-filter').value.trim();
    const hasError = byId('traffic-error-filter').value;
    if (method) params.set('method', method);
    if (endpoint) params.set('endpoint', endpoint);
    if (statusText !== '' && /^\d{1,3}$/.test(statusText)) params.set('status', statusText);
    if (module) params.set('module', module);
    if (hasError !== '') params.set('has_error', hasError);
    params.set('limit', String(state.trafficLimit));
    params.set('offset', String(state.trafficOffset));
    return params;
  }

  async function loadTrafficPage(reset = false) {
    const scanId = byId('traffic-scan-select').value || state.trafficScanId;
    if (!scanId) {
      trafficMessage('Select a scan to view recorded HTTP exchanges.');
      return;
    }
    state.trafficScanId = scanId;
    if (reset) state.trafficOffset = 0;
    const body = byId('traffic-table-body');
    trafficMessage('Loading recorded HTTP exchanges…');
    try {
      const query = trafficFilters();
      const response = await fetch(`/api/vf/scans/${encodeURIComponent(scanId)}/traffic?${query}`,
        { headers: { Accept: 'application/json' } });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
      state.trafficItems = Array.isArray(result.items) ? result.items : [];
      state.trafficHasMore = Boolean(result.has_more);
      body.replaceChildren();
      if (!state.trafficItems.length) {
        trafficMessage('No recorded HTTP exchanges match these filters.');
        state.trafficHasMore = false;
        byId('traffic-prev').disabled = state.trafficOffset <= 0;
        byId('traffic-next').disabled = true;
        return;
      }
      state.trafficItems.forEach((item, index) => {
        const row = document.createElement('tr');
        row.dataset.exchangeId = String(item.exchange_id || '');
        if (row.dataset.exchangeId === state.trafficExchangeId) row.classList.add('is-selected');
        const urlText = String(item.url || '');
        let host = '—';
        try { host = new URL(urlText).host; } catch { /* retain safe fallback */ }
        const values = [String(state.trafficOffset + index + 1), host,
          String(item.method || '—'), urlText, item.status == null ? '—' : String(item.status),
          String(item.module || '—'), `${item.request_bytes ?? 0} ch`, `${item.response_bytes ?? 0} ch`];
        values.forEach((value, cellIndex) => {
          const cell = document.createElement('td');
          cell.textContent = value;
          if (cellIndex === 2) {
            const chip = document.createElement('span');
            chip.className = 'method-chip';
            chip.textContent = value;
            cell.replaceChildren(chip);
          }
          if (cellIndex === 3) cell.className = 'traffic-url-cell';
          if (cellIndex === 4) {
            cell.className = 'status-code';
            cell.dataset.status = value;
          }
          row.append(cell);
        });
        row.addEventListener('click', () => selectTrafficExchange(item.exchange_id, row));
        body.append(row);
      });
      const first = state.trafficOffset + 1;
      const last = state.trafficOffset + state.trafficItems.length;
      byId('traffic-summary').textContent = `Showing ${first}–${last} · ${state.trafficItems.length} exchange(s) on this page`;
      byId('traffic-prev').disabled = state.trafficOffset <= 0;
      byId('traffic-next').disabled = !state.trafficHasMore;
      if (!state.trafficExchangeId && state.trafficItems[0]) {
        const firstRow = body.querySelector('tr[data-exchange-id]');
        selectTrafficExchange(state.trafficItems[0].exchange_id, firstRow);
      }
    } catch (error) {
      trafficMessage(`Could not load HTTP history: ${error.message}`);
      byId('traffic-prev').disabled = true;
      byId('traffic-next').disabled = true;
    }
  }

  function renderRequest(exchange) {
    let path = String(exchange.url || '');
    let host = '';
    try {
      const url = new URL(path);
      host = url.host;
      path = `${url.pathname || '/'}${url.search}`;
    } catch { /* show stored URL verbatim as inert text */ }
    const headers = exchange.request_headers && typeof exchange.request_headers === 'object'
      ? exchange.request_headers : {};
    const headerItems = (Array.isArray(exchange.request_header_items)
      ? exchange.request_header_items.filter((item) => Array.isArray(item) && item.length >= 2)
      : Object.entries(headers)).filter(([name]) => !['connection', 'content-length', 'transfer-encoding', 'proxy-connection', 'upgrade'].includes(String(name).toLowerCase()));
    const version = String(exchange.request_version || 'HTTP/1.1');
    const lines = [`${exchange.method || 'GET'} ${path || '/'} ${version}`];
    if (host && !headerItems.some(([name]) => String(name).toLowerCase() === 'host')) lines.push(`Host: ${host}`);
    headerItems.forEach(([name, value]) => lines.push(`${name}: ${value}`));
    lines.push('', String(exchange.request_body || ''));
    return lines.join('\n');
  }

  function renderResponse(exchange) {
    const status = Number(exchange.status || 0);
    const version = String(exchange.response_version || 'HTTP/1.1');
    const reason = String(exchange.reason_phrase || '');
    const lines = [status > 0 ? `${version} ${status}${reason ? ` ${reason}` : ''}` : 'No HTTP response was recorded'];
    if (exchange.error) lines.push(`Engine note: ${exchange.error}`);
    const headers = exchange.response_headers && typeof exchange.response_headers === 'object'
      ? exchange.response_headers : {};
    const headerItems = Array.isArray(exchange.response_header_items)
      ? exchange.response_header_items.filter((item) => Array.isArray(item) && item.length >= 2)
      : Object.entries(headers);
    headerItems.forEach(([name, value]) => lines.push(`${name}: ${value}`));
    lines.push('', String(exchange.response_body || ''));
    if (!exchange.response_body) lines.push('[No response body recorded]');
    return lines.join('\n');
  }

  function renderTrafficInspector(side) {
    const exchange = state.selectedExchange;
    const view = state.inspectorViews[side] || 'raw';
    const output = byId(side === 'request' ? 'traffic-request-view' : 'traffic-response-view');
    const renderer = window.VulnForgeTrafficInspector;
    if (!output) return;
    output.textContent = renderer
      ? renderer.render(exchange, side, view, side === 'request' ? renderRequest : renderResponse)
      : (side === 'request' ? renderRequest(exchange || {}) : renderResponse(exchange || {}));
    document.querySelectorAll(`[data-traffic-side="${side}"][data-traffic-view]`).forEach((tab) => {
      const active = tab.dataset.trafficView === view;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', String(active));
    });
  }

  function selectTrafficInspectorView(side, view) {
    if (!['request', 'response'].includes(side)) return;
    state.inspectorViews[side] = view;
    renderTrafficInspector(side);
  }

  async function selectTrafficExchange(exchangeId, row = null) {
    if (!exchangeId) return;
    state.trafficExchangeId = exchangeId;
    document.querySelectorAll('#traffic-table-body tr[data-exchange-id]').forEach((item) => item.classList.remove('is-selected'));
    if (row) row.classList.add('is-selected');
    byId('traffic-request-view').textContent = 'Loading captured request…';
    byId('traffic-response-view').textContent = 'Loading captured response…';
    try {
      const response = await fetch(`/api/vf/traffic/${encodeURIComponent(exchangeId)}`,
        { headers: { Accept: 'application/json' } });
      const exchange = await response.json();
      if (!response.ok) throw new Error(exchange.detail || `Request failed (${response.status})`);
      state.selectedExchange = exchange;
      renderTrafficInspector('request');
      renderTrafficInspector('response');
      const secretMode = exchange.sensitive_values_stored ? 'sensitive values stored in plaintext' : 'sensitive values redacted';
      byId('traffic-request-meta').textContent = `${exchange.method || 'HTTP'} ${exchange.module || 'scan'} · prepared request headers · ${secretMode}`;
      const timing = Number(exchange.duration_ms);
      byId('traffic-response-meta').textContent = `${exchange.status || 'No response'}${Number.isFinite(timing) && timing > 0 ? ` · ${timing.toFixed(1)} ms` : ''} · response ${exchange.response_id || ''} · ${secretMode}`;
      byId('traffic-request-meta').textContent = `${exchange.method || 'HTTP'} ${exchange.module || 'scan'} · request ${exchange.request_id || ''} · parent ${exchange.parent_exchange_id || 'none'} · ${secretMode}`;
    } catch (error) {
      state.selectedExchange = null;
      byId('traffic-request-view').textContent = `Could not load request: ${error.message}`;
      byId('traffic-response-view').textContent = `Could not load response: ${error.message}`;
    }
  }

  async function loadSelectedExchangeIntoRepeater() {
    if (!state.trafficExchangeId) return;
    try {
      const response = await fetch(`/api/vf/traffic/${encodeURIComponent(state.trafficExchangeId)}`, { headers: { Accept: 'application/json' } });
      const exchange = await response.json();
      if (!response.ok) throw new Error(exchange.detail || `Request failed (${response.status})`);
      state.repeaterSourceExchangeId = exchange.exchange_id;
      byId('repeater-raw-request').value = renderRequest(exchange);
      byId('repeater-raw-response').textContent = 'Captured response shown in HTTP traffic; this editor is ready for a scoped replay or mutation.';
      byId('repeater-source-meta').textContent = `Source ${exchange.exchange_id} · scan ${exchange.scan_id || state.trafficScanId} · original saved scope`;
      byId('repeater-authorized').checked = false;
      byId('repeater-state-change').checked = false;
      byId('repeater-status').textContent = 'Ready';
      navigate('repeater');
    } catch (error) {
      byId('traffic-request-meta').textContent = `Could not prepare Repeater request: ${error.message}`;
    }
  }

  async function compareSelectedTraffic() {
    const otherId = byId('traffic-compare-id').value.trim();
    const output = byId('traffic-diff-view');
    if (!state.trafficExchangeId || !otherId) {
      output.textContent = 'Select an exchange and enter another stored exchange ID.';
      return;
    }
    output.textContent = 'Comparing stored responses…';
    try {
      const params = new URLSearchParams({ exchange_a: state.trafficExchangeId, exchange_b: otherId });
      const response = await fetch(`/api/vf/traffic/diff?${params}`, { headers: { Accept: 'application/json' } });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
      output.textContent = JSON.stringify(result, null, 2);
    } catch (error) { output.textContent = `Comparison failed: ${error.message}`; }
  }

  async function copyTrafficPane(button) {
    const target = byId(button.dataset.copyTarget);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent || '');
      const old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = old; }, 1200);
    } catch {
      button.textContent = 'Copy unavailable';
      setTimeout(() => { button.textContent = 'Copy'; }, 1500);
    }
  }

  function init() {
    document.querySelectorAll('[data-route]').forEach((control) => {
      control.addEventListener('click', (event) => {
        event.preventDefault();
        navigate(control.dataset.route);
      });
    });
    byId('menu-toggle').addEventListener('click', () => {
      const open = !byId('sidebar').classList.contains('is-open');
      byId('sidebar').classList.toggle('is-open', open);
      byId('sidebar-scrim').classList.toggle('is-visible', open);
      byId('menu-toggle').setAttribute('aria-expanded', String(open));
      byId('menu-toggle').setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    });
    byId('sidebar-scrim').addEventListener('click', closeMobileNav);
    byId('refresh-repeater').addEventListener('click', loadRepeaterHistory);
    byId('btn-repeater-send').addEventListener('click', sendRepeaterRequest);
    byId('console-connect-form').addEventListener('submit', connectConsole);
    byId('console-disconnect').addEventListener('click', () => disconnectConsole());
    byId('scan-start-form').addEventListener('submit', startVfScan);
    byId('utility-form').addEventListener('submit', runUtility);
    byId('settings-refresh').addEventListener('click', loadSettingsPage);
    byId('events-refresh').addEventListener('click', loadEventsPage);
    byId('events-more').addEventListener('click', loadMoreEvents);
    byId('events-scan-select').addEventListener('change', () => { state.eventScanId=byId('events-scan-select').value; loadEventsPage(); });
    byId('events-search').addEventListener('input', renderStoredEvents);
    byId('scan-live-traffic').addEventListener('click', () => navigate('traffic'));
    byId('scans-refresh').addEventListener('click', loadScansPage);
    byId('workbench-refresh').addEventListener('click', loadDashboard);
    byId('workbench-scan-select').addEventListener('change', () => { state.workbenchScanId=byId('workbench-scan-select').value; loadWorkbenchScan(state.workbenchScanId); });
    byId('workbench-to-repeater')?.addEventListener('click', loadSelectedExchangeIntoRepeater);
    byId('workbench-target-search')?.addEventListener('input', (e) => {
      renderWorkbenchSitemap(state.workbenchScanId, state.wbEndpointsCache, e.target.value);
      renderWorkbenchTraffic(state.wbExchangesCache, e.target.value);
    });
    byId('workbench-history-filter')?.addEventListener('input', (e) => {
      renderWorkbenchTraffic(state.wbExchangesCache, e.target.value);
    });
    document.querySelectorAll('[data-wb-side][data-wb-view]').forEach((tab) => {
      tab.addEventListener('click', () => {
        state.wbInspectorViews[tab.dataset.wbSide] = tab.dataset.wbView;
        renderWorkbenchCodePane(tab.dataset.wbSide);
      });
    });
    document.querySelectorAll('[data-wb-rep-tab]').forEach((tab) => {
      tab.addEventListener('click', () => {
        state.wbRepeaterTab = tab.dataset.wbRepTab;
        renderWorkbenchMiniRepeaterPane();
      });
    });
    byId('wb-rep-send')?.addEventListener('click', sendWorkbenchMiniRepeater);
    document.querySelectorAll('[data-issue-severity]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const sevSelect = byId('finding-severity-filter');
        if (sevSelect) sevSelect.value = btn.dataset.issueSeverity;
        navigate('findings');
      });
    });
    byId('scan-detail-traffic').addEventListener('click', () => { if (state.selectedScanId) { state.trafficScanId=state.selectedScanId; navigate('traffic'); } });
    byId('endpoints-refresh').addEventListener('click', loadEndpointsPage);
    byId('endpoints-scan-filter').addEventListener('change', loadEndpointsPage);
    byId('parameters-refresh').addEventListener('click', loadParametersPage);
    byId('parameters-scan-select').addEventListener('change',()=>{state.parameterScanId=byId('parameters-scan-select').value;loadParametersPage();});
    byId('parameters-location-filter').addEventListener('change',loadParametersPage);
    let parameterSearchTimer;
    byId('parameters-search').addEventListener('input',()=>{clearTimeout(parameterSearchTimer);parameterSearchTimer=setTimeout(loadParametersPage,250);});
    byId('research-refresh').addEventListener('click',()=>loadResearchPage(true));
    byId('research-more').addEventListener('click',()=>loadResearchPage(false));
    byId('research-scan-select').addEventListener('change',()=>{state.researchScanId=byId('research-scan-select').value;loadResearchPage(true);});
    byId('research-kind-select').addEventListener('change',()=>loadResearchPage(true));
    let researchSearchTimer;
    byId('research-search').addEventListener('input',()=>{clearTimeout(researchSearchTimer);researchSearchTimer=setTimeout(()=>loadResearchPage(true),250);});
    let endpointSearchTimer;
    byId('endpoints-search').addEventListener('input', () => { clearTimeout(endpointSearchTimer); endpointSearchTimer=setTimeout(loadEndpointsPage,250); });
    byId('technology-refresh').addEventListener('click', loadTechnologiesPage);
    let technologySearchTimer;
    byId('technology-search').addEventListener('input', () => { clearTimeout(technologySearchTimer); technologySearchTimer=setTimeout(loadTechnologiesPage,250); });
    byId('findings-refresh').addEventListener('click', () => loadFindingsPage(false));
    byId('finding-status-filter').addEventListener('change', () => loadFindingsPage(false));
    byId('finding-severity-filter').addEventListener('change', () => loadFindingsPage(false));
    let findingSearchTimer;
    byId('finding-search').addEventListener('input', () => { clearTimeout(findingSearchTimer); findingSearchTimer=setTimeout(() => loadFindingsPage(false),250); });
    byId('evidence-refresh').addEventListener('click', loadEvidencePage);
    byId('evidence-scan-filter').addEventListener('change', loadEvidencePage);
    document.querySelectorAll('.traffic-tab').forEach((tab) => {
      tab.addEventListener('click', () => selectTrafficInspectorView(tab.dataset.trafficSide, tab.dataset.trafficView));
    });
    byId('traffic-scan-select').addEventListener('change', () => {
      state.trafficExchangeId = '';
      state.selectedExchange = null;
      state.trafficScanId = byId('traffic-scan-select').value;
      if (state.trafficRefreshTimer) clearInterval(state.trafficRefreshTimer);
      state.trafficRefreshTimer = setInterval(refreshTrafficIfRunning, 2500);
      loadTrafficPage(true);
      refreshTrafficIfRunning();
    });
    byId('traffic-method-filter').addEventListener('change', () => loadTrafficPage(true));
    byId('traffic-status-filter').addEventListener('input', () => loadTrafficPage(true));
    byId('traffic-error-filter').addEventListener('change', () => loadTrafficPage(true));
    byId('traffic-module-filter').addEventListener('input', () => {
      clearTimeout(window.vfModuleFilterTimer);
      window.vfModuleFilterTimer = setTimeout(() => loadTrafficPage(true), 250);
    });
    byId('traffic-to-repeater').addEventListener('click', loadSelectedExchangeIntoRepeater);
    byId('traffic-compare').addEventListener('click', compareSelectedTraffic);
    let trafficSearchTimer;
    byId('traffic-search-filter').addEventListener('input', () => {
      clearTimeout(trafficSearchTimer);
      trafficSearchTimer = setTimeout(() => loadTrafficPage(true), 250);
    });
    byId('traffic-refresh').addEventListener('click', () => loadTrafficPage(true));
    byId('traffic-prev').addEventListener('click', () => {
      state.trafficOffset = Math.max(0, state.trafficOffset - state.trafficLimit);
      loadTrafficPage();
    });
    byId('traffic-next').addEventListener('click', () => {
      state.trafficOffset += state.trafficLimit;
      loadTrafficPage();
    });
    document.querySelectorAll('[data-copy-target]').forEach((button) => {
      button.addEventListener('click', () => copyTrafficPane(button));
    });
    window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));
    navigate(location.hash.slice(1) || 'dashboard', false);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
