"""
Certificate Chain Visualizer — Web UI for drawing trust chains.

Connects to all Dogtag PKI CAs and renders interactive trust chain diagrams
showing the relationship between Root CA, Intermediate CA, Sub-CAs, and
issued certificates across RSA, ECC, and PQ hierarchies.

Endpoints:
  GET  /                HTML visualization page
  GET  /api/chains      JSON trust chain data for all hierarchies
  GET  /api/chain/{pki} JSON trust chain for specific PKI type
  GET  /health          Health check
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("chain-visualizer")

app = FastAPI(
    title="Certificate Chain Visualizer",
    description="Interactive PKI trust chain visualization",
    version="1.0.0",
)

# CA endpoints (host-gateway ports)
CA_HIERARCHY = {
    "rsa": {
        "label": "RSA-4096 PKI",
        "color": "#4CAF50",
        "cas": [
            {"level": "root", "name": "RSA Root CA", "host": "root-ca.cert-lab.local", "port": 8443},
            {"level": "intermediate", "name": "RSA Intermediate CA", "host": "intermediate-ca.cert-lab.local", "port": 8444, "parent": "root"},
            {"level": "iot", "name": "RSA IoT Sub-CA", "host": "iot-ca.cert-lab.local", "port": 8445, "parent": "intermediate"},
            {"level": "est", "name": "RSA EST RA", "host": "est-ca.cert-lab.local", "port": 8447, "parent": "intermediate", "type": "ra"},
            {"level": "acme", "name": "RSA ACME RA", "host": "acme-ca.cert-lab.local", "port": 8446, "parent": "intermediate", "type": "ra"},
            {"level": "ocsp", "name": "RSA OCSP", "host": "ocsp.cert-lab.local", "port": 8448, "parent": "intermediate", "type": "ocsp"},
            {"level": "kra", "name": "RSA KRA", "host": "kra.cert-lab.local", "port": 8449, "parent": "intermediate", "type": "kra"},
        ],
    },
    "ecc": {
        "label": "ECC P-384 PKI",
        "color": "#2196F3",
        "cas": [
            {"level": "root", "name": "ECC Root CA", "host": "ecc-root-ca.cert-lab.local", "port": 8463},
            {"level": "intermediate", "name": "ECC Intermediate CA", "host": "ecc-intermediate-ca.cert-lab.local", "port": 8464, "parent": "root"},
            {"level": "iot", "name": "ECC IoT Sub-CA", "host": "ecc-iot-ca.cert-lab.local", "port": 8465, "parent": "intermediate"},
            {"level": "est", "name": "ECC EST RA", "host": "ecc-est-ca.cert-lab.local", "port": 8466, "parent": "intermediate", "type": "ra"},
            {"level": "ocsp", "name": "ECC OCSP", "host": "ecc-ocsp.cert-lab.local", "port": 8467, "parent": "intermediate", "type": "ocsp"},
            {"level": "kra", "name": "ECC KRA", "host": "ecc-kra.cert-lab.local", "port": 8468, "parent": "intermediate", "type": "kra"},
        ],
    },
    "pqc": {
        "label": "ML-DSA-87 PKI (Post-Quantum)",
        "color": "#FF9800",
        "cas": [
            {"level": "root", "name": "PQ Root CA", "host": "pq-root-ca.cert-lab.local", "port": 8453},
            {"level": "intermediate", "name": "PQ Intermediate CA", "host": "pq-intermediate-ca.cert-lab.local", "port": 8454, "parent": "root"},
            {"level": "iot", "name": "PQ IoT Sub-CA", "host": "pq-iot-ca.cert-lab.local", "port": 8455, "parent": "intermediate"},
            {"level": "est", "name": "PQ EST RA", "host": "pq-est-ca.cert-lab.local", "port": 8456, "parent": "intermediate", "type": "ra"},
            {"level": "ocsp", "name": "PQ OCSP", "host": "pq-ocsp.cert-lab.local", "port": 8457, "parent": "intermediate", "type": "ocsp"},
            {"level": "kra", "name": "PQ KRA", "host": "pq-kra.cert-lab.local", "port": 8458, "parent": "intermediate", "type": "kra"},
        ],
    },
}


async def check_ca(host: str, port: int, ca_type: str = "ca") -> dict:
    """Check CA status and get cert count."""
    info = {"up": False, "certs_valid": 0, "certs_revoked": 0}

    status_paths = {
        "ca": "/ca/admin/ca/getStatus",
        "ra": "/ca/admin/ca/getStatus",
        "ocsp": "/ocsp/admin/ocsp/getStatus",
        "kra": "/kra/admin/kra/getStatus",
    }
    path = status_paths.get(ca_type, "/ca/admin/ca/getStatus")

    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(f"https://{host}:{port}{path}")
            if resp.status_code == 200 and "running" in resp.text.lower():
                info["up"] = True

            if ca_type in ("ca", "ra") and info["up"]:
                # Get cert counts
                for status in ("VALID", "REVOKED"):
                    try:
                        r = await client.get(
                            f"https://{host}:{port}/ca/rest/certs?size=1&status={status}",
                            headers={"Accept": "application/json"},
                        )
                        if r.status_code == 200:
                            info[f"certs_{status.lower()}"] = r.json().get("total", 0)
                    except Exception:
                        pass
    except Exception:
        pass

    return info


async def get_chain_data(pki_type: str = None):
    """Get chain data for one or all PKI types."""
    types = [pki_type] if pki_type else list(CA_HIERARCHY.keys())
    result = {}

    for pt in types:
        if pt not in CA_HIERARCHY:
            continue
        hierarchy = CA_HIERARCHY[pt]
        nodes = []

        tasks = []
        for ca in hierarchy["cas"]:
            tasks.append(check_ca(ca["host"], ca["port"], ca.get("type", "ca")))

        statuses = await asyncio.gather(*tasks, return_exceptions=True)

        for ca, status in zip(hierarchy["cas"], statuses):
            if isinstance(status, Exception):
                status = {"up": False, "certs_valid": 0, "certs_revoked": 0}
            nodes.append({
                **ca,
                **status,
            })

        result[pt] = {
            "label": hierarchy["label"],
            "color": hierarchy["color"],
            "nodes": nodes,
        }

    return result


@app.get("/api/chains")
async def api_chains():
    """Get all trust chain data."""
    return await get_chain_data()


@app.get("/api/chain/{pki_type}")
async def api_chain(pki_type: str):
    """Get trust chain for a specific PKI type."""
    return await get_chain_data(pki_type)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "chain-visualizer"}


@app.get("/", response_class=HTMLResponse)
async def index():
    """Render the chain visualization page."""
    chains = await get_chain_data()
    return f"""<!DOCTYPE html>
<html><head>
<title>PKI Trust Chain Visualizer</title>
<style>
  body {{ font-family: sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
  h1 {{ text-align: center; color: #e94560; }}
  .hierarchies {{ display: flex; justify-content: center; gap: 40px; flex-wrap: wrap; }}
  .hierarchy {{ background: #16213e; border-radius: 12px; padding: 20px; min-width: 280px; }}
  .hierarchy h2 {{ text-align: center; margin-top: 0; }}
  .node {{ border: 2px solid; border-radius: 8px; padding: 10px; margin: 8px 0; position: relative; }}
  .node.up {{ opacity: 1; }}
  .node.down {{ opacity: 0.4; border-style: dashed; }}
  .node .name {{ font-weight: bold; }}
  .node .info {{ font-size: 0.85em; color: #aaa; margin-top: 4px; }}
  .node .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; }}
  .badge.up {{ background: #4CAF50; color: #fff; }}
  .badge.down {{ background: #f44336; color: #fff; }}
  .connector {{ border-left: 2px dashed #555; margin-left: 20px; padding-left: 15px; }}
  .sub {{ margin-left: 20px; }}
  .stats {{ text-align: center; margin-top: 20px; color: #888; font-size: 0.9em; }}
  .legend {{ display: flex; gap: 20px; justify-content: center; margin: 10px 0; font-size: 0.85em; }}
  .legend span {{ display: flex; align-items: center; gap: 5px; }}
  .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
</style>
</head><body>
<h1>PKI Trust Chain Visualizer</h1>
<div class="legend">
  <span><span class="dot" style="background:#4CAF50"></span> RSA-4096</span>
  <span><span class="dot" style="background:#2196F3"></span> ECC P-384</span>
  <span><span class="dot" style="background:#FF9800"></span> ML-DSA-87</span>
</div>
<div class="hierarchies" id="chains"></div>
<div class="stats">Auto-refreshes every 30 seconds</div>
<script>
async function render() {{
  const resp = await fetch('/api/chains');
  const data = await resp.json();
  const container = document.getElementById('chains');
  container.innerHTML = '';

  for (const [pki, info] of Object.entries(data)) {{
    const div = document.createElement('div');
    div.className = 'hierarchy';
    div.innerHTML = '<h2 style="color:' + info.color + '">' + info.label + '</h2>';

    const root = info.nodes.find(n => n.level === 'root');
    if (root) {{
      div.innerHTML += renderNode(root, info.color);
      const intermediates = info.nodes.filter(n => n.parent === 'root');
      for (const intCA of intermediates) {{
        div.innerHTML += '<div class="connector">' + renderNode(intCA, info.color);
        const children = info.nodes.filter(n => n.parent === 'intermediate');
        for (const child of children) {{
          div.innerHTML += '<div class="sub">' + renderNode(child, info.color) + '</div>';
        }}
        div.innerHTML += '</div>';
      }}
    }}
    container.appendChild(div);
  }}
}}

function renderNode(node, color) {{
  const status = node.up ? 'up' : 'down';
  const badge = node.up ? '<span class="badge up">UP</span>' : '<span class="badge down">DOWN</span>';
  let info = '';
  if (node.certs_valid || node.certs_revoked) {{
    info = `<div class="info">Valid: ${{node.certs_valid}} | Revoked: ${{node.certs_revoked}}</div>`;
  }}
  const typeLabel = node.type ? ` (${{node.type.toUpperCase()}})` : '';
  return `<div class="node ${{status}}" style="border-color:${{color}}">
    <div class="name">${{node.name}}${{typeLabel}} ${{badge}}</div>
    ${{info}}
  </div>`;
}}

render();
setInterval(render, 30000);
</script>
</body></html>"""
