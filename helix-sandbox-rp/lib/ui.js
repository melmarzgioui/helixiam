// Tiny server-rendered UI. No template engine — just tagged helpers — so the
// whole sandbox stays a couple of dependency-light files you can read top to bottom.

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const STYLE = `
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2230;--border:#2a3240;--text:#e6edf3;
--muted:#8b97a7;--accent:#3fb950;--accent2:#2f81f7;--danger:#f85149;--warn:#d29922;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font-family:'Work Sans',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header.top{display:flex;align-items:center;gap:14px;padding:18px 24px;border-bottom:1px solid var(--border);background:var(--panel)}
.logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:inline-block}
header.top h1{font-size:17px;margin:0;font-weight:600;letter-spacing:.2px}
header.top .sub{color:var(--muted);font-size:13px}
.pill{margin-left:auto;font-size:12px;padding:5px 11px;border-radius:999px;border:1px solid var(--border)}
.pill.on{color:var(--accent);border-color:#2ea04366;background:#2ea04314}
.pill.off{color:var(--muted)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:18px}
.card h2{margin:0 0 4px;font-size:15px;font-weight:600}
.card p.hint{color:var(--muted);font-size:13px;margin:0 0 16px}
.btns{display:flex;flex-wrap:wrap;gap:10px}
.btn{display:inline-flex;align-items:center;gap:7px;padding:9px 15px;border-radius:9px;border:1px solid var(--border);
background:var(--panel2);color:var(--text);font-size:14px;font-weight:500;cursor:pointer}
.btn:hover{border-color:#3d4858;text-decoration:none}
.btn.primary{background:linear-gradient(135deg,#2ea043,#238636);border-color:#2ea04366;color:#fff}
.btn.blue{background:linear-gradient(135deg,#2f81f7,#1f6feb);border-color:#2f81f766;color:#fff}
.btn.ghost{background:transparent}
.btn.danger{color:var(--danger);border-color:#f8514955}
.kv{width:100%;border-collapse:collapse;font-size:13px}
.kv td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.kv td.k{color:var(--muted);white-space:nowrap;width:1%;font-family:var(--mono)}
.kv td.v{font-family:var(--mono);word-break:break-all}
.tag{font-size:11px;padding:2px 7px;border-radius:6px;background:var(--panel2);border:1px solid var(--border);color:var(--muted)}
pre{background:#0a0e14;border:1px solid var(--border);border-radius:10px;padding:14px;overflow:auto;
font-family:var(--mono);font-size:12.5px;color:#c9d4e0;margin:0}
.section-title{display:flex;align-items:center;gap:8px;margin:22px 0 10px;font-size:13px;
text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.banner{padding:13px 16px;border-radius:10px;margin-bottom:18px;font-size:14px;border:1px solid}
.banner.ok{background:#2ea04314;border-color:#2ea04366;color:#7ee787}
.banner.err{background:#f8514914;border-color:#f8514966;color:#ffa198}
.banner.info{background:#2f81f714;border-color:#2f81f766;color:#79c0ff}
.who{display:flex;align-items:center;gap:14px}
.avatar{width:46px;height:46px;border-radius:50%;background:linear-gradient(135deg,#2f81f7,#a371f7);
display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;color:#fff}
.muted{color:var(--muted)}.mono{font-family:var(--mono)}
.foot{color:var(--muted);font-size:12px;text-align:center;padding:18px}
.flowsteps{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.step{font-size:12px;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:var(--panel2);color:var(--muted)}
.step.done{color:var(--accent);border-color:#2ea04366}
`;

export function page({ title, body, idpUp }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Work+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>${STYLE}</style></head><body>
<header class="top"><span class="logo"></span>
<div><h1>Helix IAM — Sandbox Relying Party</h1>
<div class="sub">OIDC demo client · realm <span class="mono">master</span> · client <span class="mono">helix-sandbox</span></div></div>
<span class="pill ${idpUp ? 'on' : 'off'}">IdP ${idpUp ? '● reachable' : '○ unreachable'}</span>
</header>
<div class="wrap">${body}</div>
<div class="foot">Helix IAM sandbox · tokens are shown unverified for inspection only</div>
</body></html>`;
}

export function kvTable(entries) {
  if (!entries.length) return `<p class="muted">none</p>`;
  return `<table class="kv">${entries
    .map((e) => `<tr><td class="k">${esc(e.key)}</td><td class="v">${esc(e.display ?? e.value)}</td></tr>`)
    .join('')}</table>`;
}

export { esc };
