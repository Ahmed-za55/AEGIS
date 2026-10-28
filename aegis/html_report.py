"""Self-contained HTML report (no JavaScript, no external assets).

Everything that came from the model or the user is HTML-escaped: the report
shows attacker-controlled code, so it must never be rendered as markup.
"""
import html

_CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f5f5f7;--line:#ddd;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--fg:#e8e8ea;--mut:#9a9aa3;--card:#1b1e26;--line:#2d313c;--ok:#3fb950;--bad:#f85149;--warn:#d29922}:root .b{color:#0b0d12}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:980px;margin:2rem auto;padding:0 1rem}
h1{margin-bottom:.2rem}.mut{color:var(--mut)}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
.b{padding:.1rem .5rem;border-radius:.6rem;font-size:.8rem;font-weight:600;color:#fff}
.b.executed{background:var(--ok)}.b.blocked{background:var(--bad)}.b.failed,.b.error{background:var(--warn)}
pre,code{font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
pre{background:var(--card);padding:.6rem;border-radius:.4rem;overflow-x:auto}
.card{background:var(--card);border-radius:.6rem;padding:.8rem 1rem;margin:1rem 0}
"""


def render_html(reports, log, title="AEGIS run report", benchmark_md=None) -> str:
    e = html.escape
    counts = {"executed": 0, "blocked": 0, "failed": 0}
    rows = []
    for r in reports:
        counts[r.status] = counts.get(r.status, 0) + 1
        detail = ""
        if r.reasons:
            detail += "<ul>" + "".join(f"<li>{e(x)}</li>" for x in r.reasons) + "</ul>"
        if r.stdout.strip():
            detail += f"<div>output: <code>{e(r.stdout.strip()[:300])}</code></div>"
        detail += f"<details><summary>final code</summary><pre>{e(r.code)}</pre></details>"
        rows.append(
            f"<tr><td><span class='b {e(r.status)}'>{e(r.status.upper())}</span></td>"
            f"<td>{e(r.task)}</td><td>{r.attempts}</td><td>{detail}</td></tr>")

    valid = log.verify()
    entry_rows = "".join(
        f"<tr><td>{e(str(x['index']))}</td><td>{e(x['event'])}</td>"
        f"<td>{e(str(x['data'].get('attempt', '')))}</td>"
        f"<td><code>{e(x['hash'][:16])}</code></td></tr>"
        for x in log.entries)
    verdict = ("<span class='b executed'>CHAIN VALID</span>" if valid
               else "<span class='b blocked'>CHAIN BROKEN</span>")

    bench = ""
    if benchmark_md:
        bench = (f"<h2>Red-team benchmark</h2><pre>{e(benchmark_md.strip())}</pre>")

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body>"
        f"<h1>{e(title)}</h1>"
        f"<p class='mut'>{counts['executed']} executed, {counts['blocked']} blocked, "
        f"{counts['failed']} failed</p>"
        "<table><tr><th>Status</th><th>Task</th><th>Attempts</th><th>Details</th></tr>"
        + "".join(rows) + "</table>"
        f"<h2>Audit log</h2><div class='card'>{verdict} "
        f"{len(log.entries)} entries, head <code>{e(log.head()[:16])}</code></div>"
        "<table><tr><th>#</th><th>Event</th><th>Attempt</th><th>Hash</th></tr>"
        + entry_rows + "</table>" + bench + "</body></html>")
