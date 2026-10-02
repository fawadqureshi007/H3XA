"""Report generation: HTML (print-ready), Markdown, JSON, CSV - and verification of what was written.

Design rules
* One self-contained HTML file: no external scripts, fonts or images, so opening a report never
  contacts a third party (profile photos are shown as links, not loaded).
* Everything that comes from a tool is escaped. CSV cells that could be read as spreadsheet
  formulas are neutralised.
* Files are written atomically (temp file + rename), so a crash never leaves half a report.
* Every written file is re-read and checked (`verify_report`); the result is returned to the UI.
"""
from __future__ import annotations
import csv
import html
import io
import json
import os
import tempfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from . import __version__
from .branding import KIND_LABEL, KIND_ORDER, display, display_list
from .correlate import Case, label, summarize

E = lambda s: html.escape(str(s if s is not None else ""), quote=True)
NOTICE = ("Collected from public sources and third-party services by automated tools. Matches are "
          "leads, not proof of identity: verify independently before acting on them. Use only within "
          "your legal authority and the scope you are engaged for.")
POWERED_BY = "CodenSec"
FORMATS = ("html", "json", "md", "csv")
_ALIASES = {"markdown": "md", "htm": "html"}
_STATUS_TEXT = {"ok": "Completed", "error": "Failed", "timeout": "Timed out", "unavailable": "Not installed / not ready",
                "needs_auth": "Needs credentials", "skipped": "Skipped"}


# ----------------------------------------------------------------------------- helpers
def _pretty(v) -> str:
    """Render a possibly-nested value (list/dict from a raw tool payload) as readable
    text instead of a Python repr like "['a', 'b']" or "{'k': 'v'}"."""
    if isinstance(v, (list, tuple)):
        return ", ".join(_pretty(x) for x in v) if v else ""
    if isinstance(v, dict):
        return "; ".join(f"{k}: {_pretty(x)}" for k, x in v.items() if x not in (None, "", [], {}))
    return str(v)


def _md(s) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(s if s is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _csv_safe(v) -> str:
    """Stop spreadsheet apps from executing cell content that starts with = + - @ (CSV injection)."""
    s = str(v if v is not None else "").replace("\r", " ").replace("\n", " ")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t") else s


def _duration(case: Case) -> str:
    import datetime as dt
    try:
        sec = int((dt.datetime.fromisoformat(case.finished) - dt.datetime.fromisoformat(case.started)).total_seconds())
    except Exception:
        return ""
    return f"{sec // 60}m {sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def _coverage(case: Case, s: dict) -> tuple[str, str]:
    """(level, text): how complete is this report? Shown at the top so a thin result is never
    mistaken for a clean one."""
    total = s["tool_runs"]
    if total == 0:
        return "bad", "No module ran. This report contains no collected data."
    if s["runs_ok"] == 0:
        return "bad", f"None of the {total} module runs completed - the report has no collected data."
    gaps = s["runs_need_setup"] + s["runs_failed"]
    if gaps:
        return "warn", (f"Partial coverage: {s['runs_ok']} of {total} module runs completed; "
                        f"{s['runs_need_setup']} need setup/credentials and {s['runs_failed']} failed or timed out. "
                        "Absence of results does not mean absence of data.")
    return "good", f"Full coverage: all {total} module runs completed."


def _highlights(case: Case, s: dict) -> list[str]:
    h = [f"{s['accounts']} account matches across {len({a.platform for a in case.accounts})} platform(s); "
         f"{s['accounts_multi_tool']} confirmed independently by 2+ tools, {s['accounts_high']} rated High."]
    names = [i for i in case.identity if i["kind"] == "name"]
    if names:
        h.append("Names seen: " + ", ".join(f"{n['value']} ({display_list(n['tools'])})" for n in names[:5]) + ".")
    if s["breaches"]:
        h.append(f"{s['breaches']} breach / exposure records (credential values are never included in this report).")
    pivots = [t for t in case.targets if t.depth]
    if pivots:
        h.append(f"{len(pivots)} follow-up target(s) were discovered and scanned automatically: "
                 + ", ".join(f"{t.kind} {t.value}" for t in pivots[:6]) + ".")
    if s["runs_need_setup"]:
        h.append(f"{s['runs_need_setup']} module run(s) could not execute (missing setup/credentials) - coverage is incomplete.")
    if s["runs_failed"]:
        h.append(f"{s['runs_failed']} module run(s) failed or timed out - see Module status.")
    return h


def _rows(case: Case) -> list[dict]:
    """Flat table of every result - the CSV body and the unit the verifier counts."""
    out = []
    for a in case.accounts:
        out.append({"section": "account", "subject": a.subject, "kind": a.via, "title": a.title, "value": "",
                    "confidence": a.confidence, "label": a.label, "modules": display_list(a.tools),
                    "url": a.urls[0] if a.urls else ""})
    for i in case.identity:
        out.append({"section": "identity", "subject": ", ".join(i["subjects"]), "kind": i["kind"],
                    "title": KIND_LABEL.get(i["kind"], i["kind"]), "value": i["value"], "confidence": i["confidence"],
                    "label": label(i["confidence"]), "modules": display_list(i["tools"]), "url": i.get("url", "")})
    for b in case.breaches:
        out.append({"section": "breach", "subject": b["subject"], "kind": b["kind"], "title": b["title"],
                    "value": b["value"], "confidence": b["confidence"], "label": label(b["confidence"]),
                    "modules": display_list(b["tools"]), "url": b.get("url", "")})
    for i in case.infra:
        out.append({"section": "infra", "subject": i.get("subject", ""), "kind": i["kind"], "title": i["kind"],
                    "value": i["value"], "confidence": "", "label": "", "modules": display_list(i["tools"]), "url": ""})
    for n in case.notes:
        out.append({"section": "note", "subject": n.subject, "kind": n.kind, "title": n.title,
                    "value": _pretty(n.data) if n.data else n.value, "confidence": "", "label": "",
                    "modules": display(n.tool), "url": n.url})
    return out


# ----------------------------------------------------------------------------- JSON
def to_json(case: Case) -> str:
    s = summarize(case)
    return json.dumps({
        "schema": "h3xa-report/2", "generator": f"h3xa {__version__}", "case": case.meta,
        "started": case.started, "finished": case.finished,
        "seeds": case.seeds, "summary": s, "notice": NOTICE,
        "targets": [t.__dict__ for t in case.targets],
        "accounts": [{**a.__dict__, "tools": display_list(a.tools).split(", ") if a.tools else [],
                      "label": a.label} for a in case.accounts],
        "identity": [{**i, "tools": [display(t) for t in i["tools"]]} for i in case.identity],
        "breaches": [{**b, "tools": [display(t) for t in b["tools"]]} for b in case.breaches],
        "infra": [{**i, "tools": [display(t) for t in i["tools"]]} for i in case.infra],
        "profiles": [p.to_dict() for p in case.profiles],
        "notes": [n.to_dict() for n in case.notes],
        "module_runs": [{**r.to_dict(), "tool": display(r.tool)} for r in case.runs],
    }, indent=2, default=str, ensure_ascii=False)


# ----------------------------------------------------------------------------- CSV
CSV_COLUMNS = ["section", "subject", "kind", "title", "value", "confidence", "label", "modules", "url"]


def to_csv(case: Case) -> str:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for r in _rows(case):
        w.writerow([_csv_safe(r[c]) if c != "confidence" else (f"{r[c]:.3f}" if r[c] != "" else "") for c in CSV_COLUMNS])
    return buf.getvalue()


# ----------------------------------------------------------------------------- Markdown
def to_markdown(case: Case) -> str:
    s, L, m = summarize(case), [], case.meta
    L += [f"# OSINT report: {', '.join(case.seeds)}", ""]
    info = [("Case ID", m.get("case_id")), ("Operator", m.get("operator")), ("Purpose / authorisation", m.get("purpose")),
            ("Profile", m.get("profile")), ("Modules", ", ".join(m.get("modules", []))),
            ("Period", f"{case.started} → {case.finished} ({_duration(case)})"), ("Generator", f"h3xa {__version__}")]
    L += ["| | |", "|---|---|"] + [f"| {k} | {_md(v)} |" for k, v in info if v]
    lvl, cov = _coverage(case, s)
    L += ["", "## Summary", ""] + [f"- {x}" for x in _highlights(case, s)] + ["", f"**Coverage:** {cov}", "", f"> {NOTICE}", ""]
    L += ["## Accounts", "", "| Platform | Subject | Matched via | Confidence | Modules | URL |", "|---|---|---|---|---|---|"]
    for a in case.accounts:
        L.append(f"| {_md(a.title)} | {_md(a.subject)} | {_md(a.via)} | {a.label} ({a.confidence:.2f}) | "
                 f"{_md(display_list(a.tools))} | {_md(a.urls[0] if a.urls else '')} |")
    L += ["", "## Identity clues", "", "| Type | Value | Seen by | Confidence |", "|---|---|---|---|"]
    for i in case.identity:
        L.append(f"| {_md(KIND_LABEL.get(i['kind'], i['kind']))} | {_md(i['value'])} | {_md(display_list(i['tools']))} | {label(i['confidence'])} |")
    L += ["", "## Breach / exposure", ""]
    for b in case.breaches:
        L.append(f"- **{_md(b['title'])}** ({_md(b['subject'])}; {_md(display_list(b['tools']))})" + (f" - {_md(b['value'])}" if b["value"] else ""))
    if case.infra:
        L += ["", "## Infrastructure", ""] + [f"- {_md(i['kind'])}: {_md(i['value'])} ({_md(display_list(i['tools']))})" for i in case.infra[:200]]
    if case.notes:
        L += ["", "## Other observations", ""]
        for n in case.notes:
            detail = _pretty(n.data) if n.data else n.value
            L.append(f"- **{_md(n.title)}** ({_md(n.subject)}; {_md(display(n.tool))})" + (f" — {_md(detail)}" if detail else ""))
    L += ["", "## Pivot chain", ""]
    for t in case.targets:
        L.append(f"- {'  ' * t.depth}{t.kind}: `{t.value}` — {t.reason}")
    L += ["", "## Module status", "", "| Module | Target | Status | Findings | Checked | Time | Note |", "|---|---|---|---|---|---|---|"]
    for r in case.runs:
        note = r.message + (f" (tried {r.attempts}x)" if r.attempts > 1 else "")
        L.append(f"| {_md(display(r.tool))} | {_md(r.target)} | {r.status} | {r.findings} | {r.checked or ''} | {r.seconds}s | {_md(note)} |")
    L += ["", "---", f"_Powered by {POWERED_BY}_"]
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#f4f6fa;--card:#fff;--fg:#161a22;--mut:#5f6b7d;--line:#e1e5ec;--acc:#2d5bff;--acc2:#6a3df0;--hi:#137a3d;--md:#a86a00;--lo:#7b8494;--bad:#c62828;--hib:#e6f5ec;--mdb:#fff4de;--lob:#eef0f4;--badb:#fdeaea}
@media(prefers-color-scheme:dark){:root{--bg:#0e1015;--card:#161a22;--fg:#e8eaee;--mut:#98a0ad;--line:#272d39;--acc:#7c9bff;--acc2:#a68bff;--hi:#4cc27f;--md:#e0a43a;--lo:#8b93a1;--bad:#ff6b6b;--hib:#12281c;--mdb:#2b2210;--lob:#1e232d;--badb:#2c1717}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,"Segoe UI",Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:0 18px 64px}
.cover{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;border-radius:0 0 16px 16px;padding:26px 26px 22px;margin:0 -18px 18px}
.cover .tag{font-size:12px;letter-spacing:.14em;text-transform:uppercase;opacity:.85}
.cover h1{margin:6px 0 4px;font-size:27px;word-break:break-word}.cover .meta{display:flex;flex-wrap:wrap;gap:6px 22px;font-size:13px;opacity:.95;margin-top:10px}
.cover .meta b{opacity:.75;font-weight:600;margin-right:4px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.chip{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);border-radius:99px;padding:2px 11px;font-size:13px}.chip i{font-style:normal;opacity:.75;margin-right:5px;font-size:11px;text-transform:uppercase}
nav.toc{position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:4px 14px;font-size:13px}
h2{font-size:18px;margin:30px 0 10px;scroll-margin-top:50px}h2 small{color:var(--mut);font-weight:400;font-size:13px;margin-left:6px}
section,.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:10px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px;margin:14px 0}.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:11px 14px}
.kpi b{font-size:24px;display:block;line-height:1.15}.kpi span{color:var(--mut);font-size:12px}
.cov{border-radius:10px;padding:10px 14px;font-size:14px;border:1px solid}.cov.good{background:var(--hib);color:var(--hi);border-color:var(--hi)}.cov.warn{background:var(--mdb);color:var(--md);border-color:var(--md)}.cov.bad{background:var(--badb);color:var(--bad);border-color:var(--bad)}
.dist{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--lob);margin:8px 0 4px}.dist i{display:block;height:100%}.dist .h{background:var(--hi)}.dist .m{background:var(--md)}.dist .l{background:var(--lo)}
.legend{font-size:12.5px;color:var(--mut);display:flex;gap:16px;flex-wrap:wrap}.legend b{color:var(--fg)}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}table.sort th{cursor:pointer;user-select:none}table.sort th:hover{color:var(--acc)}
tbody tr:hover td{background:var(--bg)}td.n{white-space:nowrap}td.wrapword{word-break:break-word}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}.High{color:var(--hi);background:var(--hib)}.Medium{color:var(--md);background:var(--mdb)}.Low{color:var(--lo);background:var(--lob)}
.st{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600}.st.ok{color:var(--hi);background:var(--hib)}.st.error,.st.timeout{color:var(--bad);background:var(--badb)}.st.needs_auth,.st.unavailable,.st.skipped{color:var(--md);background:var(--mdb)}
.bar{display:inline-block;width:64px;height:6px;border-radius:9px;background:var(--lob);vertical-align:middle;margin-right:6px;overflow:hidden}.bar i{display:block;height:100%;background:var(--acc)}
.tools{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:8px}.tools input,.tools select{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}.tools input{flex:1;min-width:180px}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}code{background:var(--bg);padding:1px 5px;border-radius:4px;font-size:12.5px}
.notice{border-left:3px solid var(--md);color:var(--mut);font-size:13px}ul{margin:6px 0 6px 18px;padding:0}li{margin:3px 0}
details summary{cursor:pointer;color:var(--mut)}.sub{color:var(--mut);font-size:13px}.grp{font-weight:600;margin:12px 0 4px}
.empty{color:var(--mut);font-style:italic;padding:6px 2px}
footer{text-align:center;color:var(--mut);font-size:12px;margin-top:40px;padding-top:14px;border-top:1px solid var(--line)}footer b{color:var(--fg)}
@media print{body{background:#fff;color:#000;font-size:11.5px}nav.toc,.tools{display:none}.cover{color:#000;background:#fff;border:2px solid #222;border-radius:6px;margin:0 0 12px}
section,.card,.kpi{break-inside:avoid;border-color:#bbb}h2{break-after:avoid}tr{break-inside:avoid}.wrap{overflow:visible}a{color:#000}a[href^=http]:after{content:" (" attr(href) ")";font-size:9px;color:#444}}
"""

JS = ("function flt(){var q=document.getElementById('q').value.toLowerCase(),c=document.getElementById('lv').value;"
      "document.querySelectorAll('#acc tbody tr').forEach(function(r){var ok=r.textContent.toLowerCase().indexOf(q)>-1&&(!c||r.dataset.lv===c);r.style.display=ok?'':'none'})}"
      "function srt(t,i){var b=t.tBodies[0],rows=[].slice.call(b.rows),d=t.dataset.d=(t.dataset.d==='a'?'d':'a');"
      "rows.sort(function(x,y){var a=x.cells[i].dataset.v||x.cells[i].textContent,z=y.cells[i].dataset.v||y.cells[i].textContent,na=parseFloat(a),nz=parseFloat(z);"
      "var r=(!isNaN(na)&&!isNaN(nz))?na-nz:a.localeCompare(z);return d==='a'?r:-r});rows.forEach(function(r){b.appendChild(r)})}"
      "document.querySelectorAll('table.sort').forEach(function(t){[].forEach.call(t.tHead.rows[0].cells,function(h,i){h.onclick=function(){srt(t,i)}})});"
      "window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true})});")


def _pill(lbl, c=None):
    return f'<span class="pill {E(lbl)}">{E(lbl)}{f" {c:.2f}" if c is not None else ""}</span>'


def _link(u):
    u = str(u or "")
    return (f'<a href="{E(u)}" rel="noopener noreferrer nofollow" target="_blank">{E(u if len(u) < 60 else u[:57] + "…")}</a>'
            if u.startswith(("http://", "https://")) else E(u))


def _bar(c):
    return f'<span class="bar"><i style="width:{max(0, min(100, round(c * 100)))}%"></i></span>'


def _table(head, rows, cls="", tid=""):
    th = "".join(f"<th>{E(h)}</th>" for h in head)
    attrs = (f' id="{tid}"' if tid else "") + (f' class="{cls}"' if cls else "")
    return f'<div class="wrap"><table{attrs}><thead><tr>{th}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _empty(text):
    return f'<div class="empty">{E(text)}</div>'


def to_html(case: Case) -> str:
    s, m = summarize(case), case.meta
    lvl, cov = _coverage(case, s)
    seeds = [t for t in case.targets if not t.depth] or case.targets
    title = ", ".join(case.seeds)
    kp = [("Targets", s["targets"]), ("Accounts", s["accounts"]), ("2+ modules agree", s["accounts_multi_tool"]),
          ("High confidence", s["accounts_high"]), ("Breach records", s["breaches"]),
          ("Identity clues", s["identity_clues"]), ("Module runs OK", f"{s['runs_ok']}/{s['tool_runs']}")]
    meta = [("Case", m.get("case_id")), ("Operator", m.get("operator")), ("Profile", m.get("profile")),
            ("Period", f"{case.started} → {case.finished}" + (f" ({_duration(case)})" if _duration(case) else "")),
            ("Purpose", m.get("purpose"))]
    o = ["<!doctype html><html lang=en><head><meta charset=utf-8>"
         "<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>OSINT report - {E(title)}</title><style>{CSS}</style></head><body><main>",
         '<header class="cover"><div class="tag">OSINT investigation report</div>'
         f"<h1>{E(title)}</h1>",
         '<div class="chips">' + "".join(f"<span class=chip><i>{E(t.kind)}</i>{E(t.value)}</span>" for t in seeds) + "</div>",
         '<div class="meta">' + "".join(f"<span><b>{E(k)}</b>{E(v)}</span>" for k, v in meta if v) + "</div></header>",
         '<nav class="toc"><a href="#summary">Summary</a><a href="#accounts">Accounts</a><a href="#identity">Identity</a>'
         '<a href="#breaches">Breaches</a><a href="#profiles">Profiles</a><a href="#infra">Infrastructure</a>'
         '<a href="#notes">Observations</a><a href="#pivots">Pivot chain</a><a href="#modules">Module status</a>'
         '<a href="#method">Method</a></nav>',
         '<h2 id="summary">Summary</h2>',
         '<div class="kpis">' + "".join(f"<div class=kpi><b>{E(v)}</b><span>{E(k)}</span></div>" for k, v in kp) + "</div>",
         f'<div class="cov {lvl}">{E(cov)}</div>',
         "<section><b>Key findings</b><ul>" + "".join(f"<li>{E(x)}</li>" for x in _highlights(case, s)) + "</ul>"]
    tot = max(1, s["accounts"])
    if s["accounts"]:
        o.append('<div class="sub" style="margin-top:10px">Account confidence</div><div class="dist">'
                 f'<i class="h" style="width:{100 * s["accounts_high"] / tot:.1f}%"></i>'
                 f'<i class="m" style="width:{100 * s["accounts_medium"] / tot:.1f}%"></i>'
                 f'<i class="l" style="width:{100 * s["accounts_low"] / tot:.1f}%"></i></div>'
                 f'<div class="legend"><span><b>{s["accounts_high"]}</b> High (≥0.85)</span>'
                 f'<span><b>{s["accounts_medium"]}</b> Medium (0.60-0.84)</span><span><b>{s["accounts_low"]}</b> Low (&lt;0.60)</span></div>')
    o.append("</section>")
    o.append(f'<section class="notice">{E(NOTICE)}</section>')

    # accounts
    o.append(f'<h2 id="accounts">Accounts<small>{len(case.accounts)}</small></h2><section>')
    if case.accounts:
        o.append('<div class="tools"><input id="q" placeholder="Filter accounts…" oninput="flt()">'
                 '<select id="lv" onchange="flt()"><option value="">All confidence</option><option>High</option>'
                 '<option>Medium</option><option>Low</option></select></div>')
        rows = []
        for a in case.accounts:
            extra = ""
            if a.profile:
                extra = "<details><summary>profile data</summary>" + "<br>".join(
                    f"<b>{E(k)}</b>: {E(_pretty(v))}" for k, v in list(a.profile.items())[:12]) + "</details>"
            rows.append(f'<tr data-lv="{E(a.label)}"><td>{E(a.title)}{extra}</td><td class=wrapword>{E(a.subject)}</td><td>{E(a.via)}</td>'
                        f'<td class=n data-v="{a.confidence:.3f}">{_bar(a.confidence)}{_pill(a.label, a.confidence)}</td>'
                        f'<td>{E(display_list(a.tools))}</td><td class=wrapword>{_link(a.urls[0]) if a.urls else ""}</td></tr>')
        o.append(_table(["Platform", "Subject", "Matched via", "Confidence", "Confirmed by", "Link"], rows, "sort", "acc"))
    else:
        o.append(_empty("No accounts were found."))
    o.append("</section>")

    # identity, grouped by kind
    o.append(f'<h2 id="identity">Identity, phone &amp; location clues<small>{len(case.identity)}</small></h2><section>')
    if case.identity:
        by: dict = {}
        for i in case.identity:
            by.setdefault(i["kind"], []).append(i)
        for kind in KIND_ORDER + [k for k in by if k not in KIND_ORDER]:
            if kind not in by:
                continue
            o.append(f'<div class="grp">{E(KIND_LABEL.get(kind, kind))}</div>')
            rows = []
            for i in by[kind]:
                v = _link(i["value"]) if kind in ("photo", "link") else E(i["value"])
                rows.append(f"<tr><td class=wrapword>{v}</td><td>{E(display_list(i['tools']))}</td>"
                            f"<td>{E(', '.join(i.get('sources', [])))}</td><td>{_pill(label(i['confidence']), i['confidence'])}</td></tr>")
            o.append(_table(["Value", "Seen by", "Source", "Confidence"], rows))
        o.append('<div class="sub">Photos and links are listed as links and are not loaded, so opening this report contacts no third party.</div>')
    else:
        o.append(_empty("No identity clues were found."))
    o.append("</section>")

    # breaches
    o.append(f'<h2 id="breaches">Breach &amp; exposure<small>{len(case.breaches)}</small></h2><section>')
    if case.breaches:
        rows = []
        for b in case.breaches:
            d = "; ".join(f"{k}: {_pretty(v)}" for k, v in b["data"].items() if v not in ("", None, [], False) and k != "labels")
            rows.append(f"<tr><td class=wrapword>{E(b['subject'])}</td><td>{E(b['title'])}</td>"
                        f"<td class=wrapword>{E(b['value'])} {E(d)}</td><td>{E(display_list(b['tools']))}</td></tr>")
        o.append(_table(["Subject", "Record", "Detail", "Source"], rows))
        o.append('<div class="sub">Passwords and hashes reported by breach sources are counted but deliberately not stored or shown.</div>')
    else:
        o.append(_empty("No breach or exposure records."))
    o.append("</section>")

    # profiles
    o.append(f'<h2 id="profiles">Rich profiles<small>{len(case.profiles)}</small></h2>')
    if case.profiles:
        for p in case.profiles:
            rows = "".join(f"<tr><th>{E(k)}</th><td class=wrapword>{_link(v) if isinstance(v, str) and v.startswith('http') else E(_pretty(v))}</td></tr>"
                           for k, v in p.data.items())
            o.append(f"<div class=card><b>{E(p.title)}</b> · {E(p.subject)} · <span class=sub>{E(display(p.tool))}</span>"
                     f"<div class=wrap><table><tbody>{rows}</tbody></table></div></div>")
    else:
        o.append(f"<section>{_empty('No detailed profiles were retrieved (these need credentials for some modules).')}</section>")

    # infra
    o.append(f'<h2 id="infra">Infrastructure<small>{len(case.infra)}</small></h2><section>')
    if case.infra:
        o.append(_table(["Type", "Value", "Module"], [f"<tr><td>{E(i['kind'])}</td><td class=wrapword>{E(i['value'])}</td>"
                                                       f"<td>{E(display_list(i['tools']))}</td></tr>" for i in case.infra[:500]]))
        if len(case.infra) > 500:
            o.append(f'<div class="sub">Showing 500 of {len(case.infra)} - the full list is in the JSON/CSV export.</div>')
    else:
        o.append(_empty("No infrastructure data (domain / IP targets only)."))
    o.append("</section>")

    # notes
    o.append(f'<h2 id="notes">Other observations<small>{len(case.notes)}</small></h2><section>')
    if case.notes:
        o.append(_table(["Observation", "Subject", "Module", "Detail"],
                        [f"<tr><td>{E(n.title)}</td><td class=wrapword>{E(n.subject)}</td><td>{E(display(n.tool))}</td>"
                         f"<td class=wrapword>{E(_pretty(n.data) if n.data else n.value)}</td></tr>" for n in case.notes]))
    else:
        o.append(_empty("None."))
    o.append("</section>")

    o.append('<h2 id="pivots">How targets were found</h2><section><ul>' + "".join(
        f"<li style='margin-left:{t.depth * 18}px'><code>{E(t.kind)}</code> {E(t.value)} <span class=sub>- {E(t.reason)}</span></li>"
        for t in case.targets) + "</ul></section>")

    # module status
    rows = []
    for r in case.runs:
        note = r.message + (f" (tried {r.attempts}x)" if r.attempts > 1 else "")
        rows.append(f"<tr><td>{E(display(r.tool))}</td><td class=wrapword>{E(r.target)}</td>"
                    f"<td><span class=\"st {E(r.status)}\">{E(_STATUS_TEXT.get(r.status, r.status))}</span></td>"
                    f"<td>{r.findings}</td><td>{E(r.checked or '')}</td><td class=n>{r.seconds}s</td><td class=wrapword>{E(note)}</td></tr>")
    o.append(f'<h2 id="modules">Module status<small>{s["runs_ok"]}/{s["tool_runs"]} completed</small></h2><section>'
             + (_table(["Module", "Target", "Status", "Findings", "Checked", "Time", "Note"], rows) if rows else _empty("No module ran."))
             + "</section>")

    o.append('<h2 id="method">Method &amp; limits</h2><section><ul>'
             "<li><b>Confidence</b> = 1 − Π(1 − w) over <i>distinct</i> modules that found the same account (two modules at 0.80 give 0.96), "
             "then multiplied by 0.85 for every verified hop of the pivot chain (0.6 scraped, 0.5 guessed). "
             "It means \"this account exists and belongs to the same subject\" - not proof of identity.</li>"
             "<li><b>Labels:</b> High ≥ 0.85 · Medium 0.60-0.84 · Low &lt; 0.60.</li>"
             "<li>A phone number yields region/carrier metadata only - never the owner or a live location.</li>"
             "<li>Modules that were not ready, lacked credentials, failed or timed out are listed under Module status; "
             "their absence lowers coverage.</li>"
             "<li>Credentials found in breach data are counted, never stored or printed.</li></ul></section>")
    o.append(f"<footer>Report generated by <b>h3xa {__version__}</b> · Powered by <b>{E(POWERED_BY)}</b></footer>")
    o.append(f"<script>{JS}</script></main></body></html>")
    return "".join(o)


# ----------------------------------------------------------------------------- writing + verification
@dataclass
class ReportResult:
    paths: list = field(default_factory=list)
    checks: list = field(default_factory=list)      # (format, ok, detail)
    errors: list = field(default_factory=list)      # (format, message)

    @property
    def ok(self) -> bool:
        return not self.errors and all(ok for _, ok, _ in self.checks)


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_VOID = {"meta", "br", "hr", "img", "input", "link", "col", "area", "base", "wbr"}


class _Balance(HTMLParser):
    """Checks that every opened tag is closed in order - catches truncated or mangled HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.problem, self.scripts, self.ids = [], "", 0, set()

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
        for k, v in attrs:
            if k == "id" and v:
                self.ids.add(v)
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in _VOID or self.problem:
            return
        if not self.stack or self.stack[-1] != tag:
            self.problem = f"unexpected </{tag}> (open: {self.stack[-1] if self.stack else 'nothing'})"
        else:
            self.stack.pop()


def verify_report(path: Path, case: Case, fmt: str) -> tuple[bool, str]:
    """Re-read a written report and check it is complete and well-formed. Returns (ok, detail)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception as e:
        return False, f"cannot re-read file: {e}"
    if not text.strip():
        return False, "file is empty"
    if "Traceback (most recent call last)" in text:
        return False, "contains a Python traceback"
    rows = len(_rows(case))
    if fmt == "html":
        p = _Balance()
        try:
            p.feed(text)
            p.close()
        except Exception as e:
            return False, f"HTML parse error: {e}"
        if p.problem:
            return False, f"malformed HTML: {p.problem}"
        if p.stack:
            return False, f"unclosed tags: {', '.join(p.stack[-3:])}"
        if not text.lstrip().lower().startswith("<!doctype html"):
            return False, "missing doctype"
        if p.scripts != 1:
            return False, f"expected exactly 1 script block, found {p.scripts} (possible injection)"
        need = {"summary", "accounts", "identity", "breaches", "modules", "method"}
        if need - p.ids:
            return False, f"missing sections: {', '.join(sorted(need - p.ids))}"
        for seed in case.seeds:
            if E(seed) not in text:
                return False, f"target '{seed}' not present in report"
        return True, f"well-formed HTML, {len(text) // 1024 + 1} KB, {len(p.ids)} sections"
    if fmt == "json":
        try:
            d = json.loads(text)
        except json.JSONDecodeError as e:
            return False, f"invalid JSON: {e}"
        for k in ("summary", "accounts", "identity", "module_runs", "case"):
            if k not in d:
                return False, f"missing key '{k}'"
        if len(d["accounts"]) != len(case.accounts) or len(d["module_runs"]) != len(case.runs):
            return False, "record counts do not match the case"
        return True, f"valid JSON, {len(d['accounts'])} accounts, {len(d['module_runs'])} module runs"
    if fmt == "md":
        for h in ("# OSINT report", "## Summary", "## Accounts", "## Module status"):
            if h not in text:
                return False, f"missing heading '{h}'"
        return True, f"{text.count(chr(10))} lines"
    if fmt == "csv":
        try:
            data = list(csv.reader(io.StringIO(text)))
        except csv.Error as e:
            return False, f"invalid CSV: {e}"
        if not data or data[0] != CSV_COLUMNS:
            return False, "unexpected header row"
        if len(data) - 1 != rows:
            return False, f"expected {rows} data rows, found {len(data) - 1}"
        if any(len(r) != len(CSV_COLUMNS) for r in data):
            return False, "ragged rows"
        return True, f"{len(data) - 1} rows"
    return False, f"unknown format '{fmt}'"


def write_reports(case: Case, out_dir: Path, base: str, formats=FORMATS, verify: bool = True) -> ReportResult:
    """Write every requested format. One failing format never blocks the others."""
    res = ReportResult()
    out_dir = Path(out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        res.errors.append(("all", f"cannot create output folder {out_dir}: {e}"))
        return res
    fn = {"html": to_html, "json": to_json, "md": to_markdown, "csv": to_csv}
    for f in dict.fromkeys(_ALIASES.get(x.strip().lower(), x.strip().lower()) for x in formats if x.strip()):
        if f not in fn:
            res.errors.append((f, f"unknown format (choose from {', '.join(FORMATS)})"))
            continue
        p = out_dir / f"{base}.{f}"
        try:
            _atomic_write(p, fn[f](case))
        except Exception as e:
            res.errors.append((f, f"{type(e).__name__}: {e}"))
            continue
        res.paths.append(p)
        if verify:
            ok, detail = verify_report(p, case, f)
            res.checks.append((f, ok, detail))
    return res


def write_all(case: Case, out_dir: Path, base: str, formats=("html", "json", "md")) -> list[Path]:
    """Backwards-compatible wrapper: returns just the written paths."""
    return write_reports(case, out_dir, base, formats).paths
