"""Human-readable HTML, Markdown and dependency-free PDF report renderers."""
from __future__ import annotations
import html
import json
import re
from pathlib import Path
from .json_report import build_report_dict


def write_markdown_report(scan, path: str) -> str:
    d = build_report_dict(scan); intel = d.get("intelligence", {})
    lines = ["# VulnForge Security Assessment", "", f"- **Target:** {d['scan']['target']}",
             f"- **Scan ID:** `{d['scan']['scan_id']}`", f"- **Started:** {d['scan']['started_at']}",
             f"- **Duration:** {d['scan']['duration_s']} s", "", "## Executive summary", "",
             f"- Requests sent: {d['statistics']['requests_sent']}",
             f"- Endpoints: {d['statistics']['endpoints_discovered']}",
             f"- Parameters: {d['statistics']['parameters_discovered']}",
             f"- Confirmed findings: {len(d.get('verified_findings',d['findings']))}",
             f"- Candidates: {len(d.get('candidates',[]))}",
             "", "## Result-state summary", ""]
    for group, counts in d.get("result_summary", {}).items():
        lines.append(f"- {group.title()}: " + ", ".join(f"{state} {count}" for state, count in counts.items() if count))
    lines += ["", "## Technology profile", ""]
    for t in d.get("technologies", []):
        lines.append(f"- **{t['name']}** ({t['category']}, {t['confidence']}) — " + "; ".join(t.get("signals", [])))
    lines += ["", "## Infrastructure and controls", "", f"- Observed IPs: {', '.join(intel.get('dns',{}).get('observed_addresses', [])) or 'Not determined'}",
              f"- TLS: {intel.get('tls',{}).get('status','Not determined')}",
              f"- Authentication: {intel.get('authentication',{}).get('status','Not determined')}",
              f"- MFA: {intel.get('mfa',{}).get('status','Not determined')}"]
    lines += ["", "## Live-service classification", ""]
    lines += [f"- **{state}**: {count}" for state,count in sorted(d.get("live_state_counts",{}).items())] or ["No crawl outcomes recorded."]
    lines += ["", "## Attack surface", "", f"- Endpoints: {len(d['endpoints'])}",
              f"- Hypotheses: {len(d.get('hypotheses', []))}", "", "## Confirmed findings", ""]
    if not d["findings"]: lines.append("No findings were recorded.")
    for f in d["findings"]:
        lines += [f"### {f['severity'].upper()} — {f['title']}", "", f"Result: **{f.get('result_status',f['status'])}** (engine state: `{f['status']}`)", "",
                  f"Endpoint: `{f.get('endpoint') or 'N/A'}`", "", f.get("description", ""), "",
                  f"Impact: {f.get('impact') or 'Not established'}", ""]
    lines += ["", "## Candidates and observations", ""]
    lines += [f"- **{f.get('result_status',f['status'])}** {f['title']} — {f.get('description','')}" for f in d.get("candidates",[])] or ["No candidate records."]
    lines += ["", "## Vulnerability test matrix", "",
              f"Priority profile: **{d.get('scan',{}).get('test_profile','full').upper()}**", "",
              "| Class | Selected | Status | Planned | Executed | Verified | Reason |", "|---|---:|---|---:|---:|---:|---|"]
    lines += [f"| {row['name']} | {'yes' if row['selected'] else 'no'} | {row.get('result_status',row['status'])} | {row['planned']} | {row['executed']} | {row['verified']} | {row['reason'].replace('|','/')} |"
              for row in d.get("vulnerability_matrix",[])] or ["No vulnerability class matrix was generated."]
    lines += ["", "## Tests performed", ""]
    lines += [f"- `{t.get('test_id','n/a')}` — {t.get('type','test')}: **{t.get('result_status',t['status'])}** — {t.get('endpoint','')}" for t in d.get("tests", [])] or ["No controlled verification tests were performed."]
    lines += ["", "## Hypotheses", ""]
    lines += [f"- `{h['status']}` {h.get('type',h.get('category','unknown'))} — `{h.get('endpoint','')}` parameter `{h.get('parameter','')}`: {h['reason']}" for h in d.get("hypotheses", [])] or ["No review hypotheses generated."]
    lines += ["", "## Phase status", ""]
    lines += [f"- **{p['phase_id']} {p['name']}** — {p['status']}: {p.get('note','')}" for p in d.get("phases",[])] or ["Phase state unavailable."]
    lines += ["", "## Coverage matrix", ""]
    lines += [f"- **{c['status']}** — {c['category']}: {c['notes']}" for c in d.get("coverage",[])] or ["Coverage matrix unavailable."]
    lines += ["", "## Coverage and limitations", "", "Coverage records work actually performed. TLS certificate details and DNS record types beyond system-resolver addresses may be undetermined.", "", "Automated observations are not proof of exploitability; validate before reporting a security issue."]
    Path(path).parent.mkdir(parents=True, exist_ok=True); Path(path).write_text("\n".join(lines)+"\n", encoding="utf-8"); return path


def write_html_report(scan, path: str) -> str:
    d=build_report_dict(scan); intel=d.get("intelligence", {})
    def e(x): return html.escape(str(x if x is not None else ""))
    cards = "".join(f'<article class="card"><span class="badge">{e(t["confidence"])}</span><h3>{e(t["name"])}</h3><p>{e(t["category"])}</p><details><summary>Evidence</summary><ul>' + ''.join(f'<li>{e(s)}</li>' for s in t.get("signals",[])) + '</ul></details></article>' for t in d.get("technologies",[])) or '<p>Not determined from observed evidence.</p>'
    endpoints = ''.join(f'<tr><td><span class="mchip">{e(ep["method"])}</span></td><td><code>{e(ep["path"])}</code></td><td>{e(ep["status"])}</td><td>{e(ep["source"])}</td></tr>' for ep in d.get("endpoints",[]))
    findings = ''.join(f'<article class="finding"><b class="badge">{e(f.get("result_status",f["status"]))} · {e(f["severity"]).upper()}</b><h3>{e(f["title"])}</h3><p>{e(f["description"])}</p><p><code>{e(f.get("endpoint"))}</code></p><details><summary>Evidence</summary><pre>{e(json.dumps(f.get("evidence",[]),indent=2))}</pre></details></article>' for f in d.get("findings",[])) or '<p>No findings recorded.</p>'
    candidate_html="".join(f"<article class='finding'><b class='badge'>{e(f.get('result_status',f.get('status','CANDIDATE')))} · {e(f.get('severity','info')).upper()}</b><h3>{e(f.get('title','Candidate'))}</h3><p>{e(f.get('description',''))}</p></article>" for f in d.get("candidates",[])) or "<p>No candidates recorded.</p>"
    hypotheses=''.join(f'<li><b>{e(h["status"])}</b> {e(h.get("type",h.get("category","unknown")))} — <code>{e(h.get("endpoint"))}</code> {e(h.get("parameter"))}: {e(h["reason"])}</li>' for h in d.get("hypotheses",[])) or '<li>None generated.</li>'
    tests=''.join(f'<li><code>{e(t["test_id"])}</code> {e(t["type"])} — <b>{e(t.get("result_status",t["status"]))}</b> — <code>{e(t.get("endpoint"))}</code></li>' for t in d.get("tests",[])) or '<li>No controlled tests were performed.</li>'
    controls=intel.get("security_headers",{})
    headers=''.join(f'<tr><td>{e(n)}</td><td>{v["observed"]-v["missing"]}/{v["observed"]}</td><td>{"MISSING on observed responses" if v["missing"] else "OBSERVED"}</td></tr>' for n,v in controls.items()) or '<tr><td colspan="3">No HTML page observations</td></tr>'
    live_rows=''.join(f'<tr><td>{e(state)}</td><td>{e(count)}</td></tr>' for state,count in sorted(d.get("live_state_counts",{}).items())) or '<tr><td colspan="2">No crawl outcomes recorded</td></tr>'
    matrix_rows=''.join(f'<tr><td>{e(row["name"])}</td><td>{"SELECTED" if row["selected"] else "NOT SELECTED"}</td><td>{e(row.get("result_status",row["status"]))}</td><td>{e(row["planned"])}</td><td>{e(row["executed"])}</td><td>{e(row["verified"])}</td><td>{e(row["reason"])}</td></tr>' for row in d.get("vulnerability_matrix",[])) or '<tr><td colspan="7">No vulnerability class matrix was generated</td></tr>'
    phases=''.join(f'<tr><td>{e(p["phase_id"])}</td><td>{e(p["name"])}</td><td>{e(p["status"])}</td><td>{e(p.get("note",""))}</td></tr>' for p in d.get("phases",[]))
    coverage=''.join(f'<tr><td>{e(c["category"])}</td><td>{e(c["status"])}</td><td>{e(c["notes"])}</td></tr>' for c in d.get("coverage",[]))
    all_findings = list(d.get("findings", [])) + list(d.get("candidates", []))
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in all_findings:
        sv = str(item.get("severity", "info")).lower()
        sev_counts[sv if sv in sev_counts else "info"] += 1
    total_f = sum(sev_counts.values())
    tech_pills = "".join(f'<span class="tpill">{e(t["name"])}</span>' for t in d.get("technologies", [])[:8]) or '<span class="tpill">No passive signature</span>'
    sitemap_items = "".join(f'<div class="smap-row"><span class="mchip">{e(ep.get("method","GET"))}</span><code>{e(ep.get("path") or ep.get("url") or "/")}</code><b>{e(ep.get("status") or "—")}</b></div>' for ep in d.get("endpoints", [])[:25]) or '<div class="smap-row">No endpoints recorded</div>'
    finding_rows = "".join(f'<tr><td>{idx}</td><td>{e(f.get("title") or f.get("category"))}</td><td><span class="badge">{e(str(f.get("severity","info")).upper())}</span></td><td><code>{e(f.get("endpoint") or "—")}</code></td></tr>' for idx, f in enumerate(all_findings[:8], 1)) or '<tr><td colspan="4">No findings recorded</td></tr>'
    html_doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>VulnForge — {e(d['scan']['target'])}</title><style>
:root{{--bg:#0b0f17;--panel:#101722;--text:#e7edf7;--muted:#94a3b8;--accent:#f97316;--teal:#50d2bd;--line:#202c3d}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 Inter,system-ui,sans-serif}}header.topstrip{{display:flex;justify-content:space-between;align-items:center;padding:10px 20px;background:#0d121b;border-bottom:1px solid var(--line)}}.wb-banner{{background:#131c2b;border-bottom:1px solid var(--line);padding:8px 20px;color:#cbd5e1;font-size:12px}}main{{max-width:1440px;margin:14px auto;padding:0 16px}}h1{{margin:0;font-size:22px}}h2{{margin-top:26px;color:var(--teal);border-bottom:1px solid var(--line);padding-bottom:6px;font-size:15px}}h3{{margin:7px 0;font-size:13px}}p,.muted{{color:var(--muted)}}.wb-grid{{display:grid;grid-template-columns:250px minmax(0,1fr);gap:12px;margin-bottom:18px}}.wb-cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;margin-top:10px}}. grid,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}.card,.finding,.metric,.wb-panel{{background:var(--panel);padding:14px;border:1px solid var(--line);border-radius:8px}}.badge{{display:inline-block;color:#08131d;background:var(--teal);font-size:10px;font-weight:800;padding:2px 7px;border-radius:6px}}.mchip{{display:inline-block;padding:1px 5px;border-radius:4px;background:#172b42;color:#60a5fa;font:700 9px ui-monospace,monospace}}.tpill{{display:inline-block;margin:2px 4px 2px 0;padding:3px 8px;border:1px solid #273952;border-radius:5px;background:#142032;color:#bfdbfe;font-size:11px;font-weight:600}}.smap-row{{display:grid;grid-template-columns:42px minmax(0,1fr) auto;gap:6px;padding:4px 0;border-bottom:1px dashed #1b2638;font:11px ui-monospace,monospace}}.metrics{{display:flex;gap:10px;flex-wrap:wrap}}.metric strong{{display:block;font-size:20px;color:#f8fafc}}table{{width:100%;border-collapse:collapse;background:var(--panel);font-size:12px}}td,th{{padding:7px 9px;border:1px solid var(--line);text-align:left}}th{{background:#141d2b;color:#94a3b8;font-size:10px;text-transform:uppercase}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#b4f0e6;font-family:ui-monospace,monospace}}details{{margin:8px 0}}summary{{cursor:pointer;color:var(--teal)}}.finding{{margin:10px 0}}footer{{margin-top:40px;color:var(--muted);border-top:1px solid var(--line);padding:18px 0}}</style></head><body><header class="topstrip"><div><small style="color:#fb923c;font-weight:700">VulnForge · WEB SECURITY ASSESSMENT</small><h1>Assessment report</h1></div><div><code>{e(d['scan']['target'])}</code> · Scan <code>{e(d['scan']['scan_id'])}</code></div></header><div class="wb-banner">Interactive Burp-style Workbench (live HTTP Request/Response/Hex inspector, Site map &amp; Guarded Repeater): run <code>vulnforge dashboard</code> and open <code>http://127.0.0.1:8000</code>.</div><main>
<div class="wb-grid"><aside class="wb-panel"><h3 style="margin-top:0">Target Site Map ({len(d['endpoints'])})</h3><div style="max-height:320px;overflow:auto">{sitemap_items}</div><h3 style="margin-top:14px">Severity Breakdown ({total_f})</h3><p style="margin:3px 0">Critical: <b>{sev_counts['critical']}</b> · High: <b>{sev_counts['high']}</b> · Medium: <b>{sev_counts['medium']}</b> · Low: <b>{sev_counts['low']}</b> · Info: <b>{sev_counts['info']}</b></p></aside><div><h2>Executive summary</h2><div class="metrics"><div class="metric"><strong>{d['statistics']['requests_sent']}</strong>Requests</div><div class="metric"><strong>{len(d['endpoints'])}</strong>Endpoints</div><div class="metric"><strong>{len(d.get('hypotheses',[]))}</strong>Hypotheses</div><div class="metric"><strong>{len(d.get('verified_findings',d['findings']))}</strong>Confirmed</div></div><div class="wb-cards"><div class="wb-panel"><h3 style="margin-top:0">Target Overview &amp; Tech Stack</h3><p>Target: <code>{e(d['scan']['target'])}</code> · Duration: {e(d['scan']['duration_s'])}s</p><div>{tech_pills}</div></div><div class="wb-panel"><h3 style="margin-top:0">Recent Findings &amp; Observations</h3><table><tr><th>#</th><th>Title</th><th>Severity</th><th>Endpoint</th></tr>{finding_rows}</table></div></div></div></div>
<h2>Target and infrastructure</h2><p>Original input: <code>{e(intel.get('target',{}).get('original_input',d['scan']['target']))}</code></p><p>Observed IPs: {e(', '.join(intel.get('dns',{}).get('observed_addresses',[])) or 'Not determined')}</p><p>TLS: {e(intel.get('tls',{}).get('status','Not determined'))} — {e(intel.get('tls',{}).get('reason',''))}</p><h2>Technology profile</h2><div class="grid">{cards}</div><h2>Authentication, MFA and cookies</h2><p>Authentication: {e(intel.get('authentication',{}).get('status','NOT DETERMINED'))}</p><p>MFA: {e(intel.get('mfa',{}).get('status','NOT DETERMINED'))}. {e(intel.get('mfa',{}).get('reason',''))}</p><p>Cookie names: {e(', '.join(c['name'] for c in intel.get('cookies',[])) or 'None observed')}</p><h2>Security headers</h2><table><tr><th>Control</th><th>Observed</th><th>Status</th></tr>{headers}</table><h2>Live-service classification</h2><table><tr><th>State</th><th>Observed</th></tr>{live_rows}</table><h2>Vulnerability test matrix · {e(d.get('scan',{}).get('test_profile','full').upper())}</h2><table><tr><th>Class</th><th>Selection</th><th>Status</th><th>Plans</th><th>Executed</th><th>Verified</th><th>Reason</th></tr>{matrix_rows}</table><h2>Attack surface</h2><p>{len(d['endpoints'])} endpoints · {len(d['parameters'])} parameters · {intel.get('coverage',{}).get('javascript_discovered',0)} JavaScript assets discovered · {intel.get('coverage',{}).get('javascript_analyzed',0)} analyzed</p><table><tr><th>Method</th><th>Path</th><th>Status</th><th>Source</th></tr>{endpoints}</table><h2>Confirmed findings</h2>{findings}<h2>Candidates and observations</h2>{candidate_html}<h2>Controlled tests</h2><ul>{tests}</ul><h2>Hypotheses (not findings)</h2><ul>{hypotheses}</ul><h2>Phase state</h2><table><tr><th>Phase</th><th>Name</th><th>Status</th><th>Notes</th></tr>{phases}</table><h2>Coverage matrix</h2><table><tr><th>Category</th><th>Status</th><th>Notes</th></tr>{coverage}</table><h2>Coverage and limitations</h2><p>Pages crawled: {intel.get('coverage',{}).get('pages_crawled',0)}. Network coverage and confidence reflect actual observations only. MFA was not tested with an authenticated workflow. No database technology is inferred without direct evidence.</p><footer>Generated by VulnForge. Automated results require human validation; candidate observations are not confirmed vulnerabilities.</footer></main></body></html>'''
    Path(path).parent.mkdir(parents=True, exist_ok=True); Path(path).write_text(html_doc,encoding="utf-8"); return path


def write_pdf_report(scan, path: str) -> str:
    """Small self-contained text PDF writer (no third-party dependency)."""
    d=build_report_dict(scan); intel=d.get("intelligence",{})
    rows=["VulnForge SECURITY ASSESSMENT",f"Target: {d['scan']['target']}",f"Scan ID: {d['scan']['scan_id']}",
          f"Duration: {d['scan']['duration_s']} seconds","", "EXECUTIVE SUMMARY",
          f"Requests: {d['statistics']['requests_sent']} | Endpoints: {len(d['endpoints'])} | Parameters: {len(d['parameters'])}",
          f"Hypotheses: {len(d.get('hypotheses',[]))} | Confirmed: {len(d.get('verified_findings',d['findings']))} | Candidates: {len(d.get('candidates',[]))}","", "TECHNOLOGY PROFILE"]
    rows += [f"{t['name']} | {t['category']} | {t['confidence']}" for t in d.get("technologies",[])] or ["Not determined"]
    rows += ["", "INFRASTRUCTURE",f"Observed IPs: {', '.join(intel.get('dns',{}).get('observed_addresses',[])) or 'Not determined'}",
             f"TLS: {intel.get('tls',{}).get('status','NOT DETERMINED')}",f"Authentication: {intel.get('authentication',{}).get('status','NOT DETERMINED')}",
             f"MFA: {intel.get('mfa',{}).get('status','NOT DETERMINED')}","", "LIVE-SERVICE CLASSIFICATION"]
    rows += [f"{state}: {count}" for state,count in sorted(d.get("live_state_counts",{}).items())] or ["No crawl outcomes recorded."]
    rows += ["", f"VULNERABILITY TEST MATRIX — {d.get('scan',{}).get('test_profile','full').upper()}"]
    rows += [f"{row['name']} | {'SELECTED' if row['selected'] else 'NOT SELECTED'} | {row.get('result_status',row['status'])} | plans {row['planned']} | executed {row['executed']} | verified {row['verified']}"
             for row in d.get("vulnerability_matrix",[])] or ["No class matrix generated."]
    rows += ["", "ATTACK SURFACE"]
    rows += [f"{ep['method']} {ep['path']} [{ep['status']}]" for ep in d['endpoints'][:120]]
    rows += ["", "FINDINGS"]
    for f in d['findings']:
        rows += [f"{f['severity'].upper()} — {f['title']} [{f.get('result_status',f['status'])}]",f"Endpoint: {f.get('endpoint','N/A')}",f['description'][:400],""]
    rows += ["", "CANDIDATES / OBSERVATIONS"]
    rows += [f"{f.get('result_status',f['status'])} — {f['title']}: {f.get('description','')[:300]}" for f in d.get('candidates',[])] or ["None recorded."]
    rows += ["CONTROLLED TESTS"]
    rows += [f"{t['test_id']} {t['type']} [{t.get('result_status',t['status'])}] {t.get('endpoint','')}" for t in d.get("tests", [])] or ["No controlled tests performed."]
    rows += ["HYPOTHESES (NOT CONFIRMED)"]
    rows += [f"{h.get('type',h.get('category','unknown'))} {h.get('endpoint','')} {h.get('parameter','')}: {h['reason']}" for h in d.get('hypotheses',[])[:100]] or ["None generated."]
    rows += ["", "PHASE STATUS"]
    rows += [f"{p['phase_id']} {p['status']} — {p['name']}" for p in d.get("phases",[])]
    rows += ["", "COVERAGE MATRIX"]
    rows += [f"{c['status']} — {c['category']}: {c['notes']}" for c in d.get("coverage",[])]
    rows += ["", "LIMITATIONS", "Automated observations are not proof of exploitability. MFA workflows were not tested unless explicitly available.", "TLS certificate details or DNS records may be undetermined."]
    # wrap & paginate at 48 lines; escape PDF literal syntax, use Helvetica.
    text=[]
    for raw in rows:
        s=str(raw).encode('latin-1','replace').decode('latin-1')
        text.extend([s[i:i+95] for i in range(0,max(1,len(s)),95)])
    pages=[text[i:i+48] for i in range(0,len(text),48)] or [[]]
    objs=[]
    def obj(x): objs.append(x.encode('latin-1','replace')); return len(objs)
    catalog=obj(''); pages_id=obj(''); font_id=obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
    page_ids=[]
    for lines in pages:
        commands=['BT','/F1 9 Tf','50 790 Td','12 TL']
        for line in lines:
            safe=line.replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
            commands.append(f'({safe}) Tj T*')
        commands.append('ET'); stream='\n'.join(commands).encode('latin-1','replace')
        content_id=obj(f'<< /Length {len(stream)} >>\nstream\n{stream.decode("latin-1")}\nendstream')
        page_id=obj(f'<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>')
        page_ids.append(page_id)
    objs[catalog-1]=f'<< /Type /Catalog /Pages {pages_id} 0 R >>'.encode()
    objs[pages_id-1]=f'<< /Type /Pages /Kids [{" ".join(f"{i} 0 R" for i in page_ids)}] /Count {len(page_ids)} >>'.encode()
    out=bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'); offsets=[0]
    for i,o in enumerate(objs,1): offsets.append(len(out)); out.extend(f'{i} 0 obj\n'.encode()); out.extend(o); out.extend(b'\nendobj\n')
    xref=len(out); out.extend(f'xref\n0 {len(objs)+1}\n0000000000 65535 f \n'.encode())
    for off in offsets[1:]: out.extend(f'{off:010d} 00000 n \n'.encode())
    out.extend(f'trailer\n<< /Size {len(objs)+1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF'.encode())
    Path(path).parent.mkdir(parents=True, exist_ok=True); Path(path).write_bytes(out); return path
