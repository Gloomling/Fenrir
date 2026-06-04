# fenrir/network_diagram.py
"""
Generates an interactive HTML network topology diagram from network scan results.

Layout:
  - Network devices (routers, switches, firewalls) — centre/top, connected to all
  - Servers — right column
  - Workstations — centre grid
  - IoT / Mobile — bottom section
  - Subnets drawn as labelled coloured regions
  - Labels positioned LEFT or RIGHT of each symbol (never crossing edges)
  - Proper network diagram symbols (SVG path icons)
  - Click device → Fenrir opens that host's results tab via localhost callback
"""

from __future__ import annotations
import ipaddress, json, threading, http.server, socketserver, webbrowser
from pathlib import Path
from typing import Optional
from fenrir.logging_config import get_logger

log = get_logger()

# ── Symbol SVG paths (all drawn in a ~40×40 viewBox centred at 0,0) ───────────
# Each value is an SVG <path d="..."> string
_SYMBOLS = {
    # Router — circle with arrows
    "router": """
      <circle cx="0" cy="0" r="18" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <path d="M-10,0 L10,0 M6,-4 L10,0 L6,4 M-6,-4 L-10,0 L-6,4
               M0,-10 L0,10 M-4,-6 L0,-10 L4,-6 M-4,6 L0,10 L4,6"
            stroke="{stroke}" stroke-width="1.5" fill="none"/>
    """,
    # Switch — rectangle with ports
    "switch": """
      <rect x="-18" y="-9" width="36" height="18" rx="3"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <line x1="-12" y1="-9" x2="-12" y2="9" stroke="{stroke}" stroke-width="1"/>
      <line x1="-4"  y1="-9" x2="-4"  y2="9" stroke="{stroke}" stroke-width="1"/>
      <line x1="4"   y1="-9" x2="4"   y2="9" stroke="{stroke}" stroke-width="1"/>
      <line x1="12"  y1="-9" x2="12"  y2="9" stroke="{stroke}" stroke-width="1"/>
      <circle cx="-12" cy="6" r="2" fill="{stroke}"/>
      <circle cx="-4"  cy="6" r="2" fill="{stroke}"/>
      <circle cx="4"   cy="6" r="2" fill="{stroke}"/>
      <circle cx="12"  cy="6" r="2" fill="{stroke}"/>
    """,
    # Firewall — brick wall
    "firewall": """
      <rect x="-18" y="-12" width="36" height="24" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <line x1="-18" y1="-4" x2="18" y2="-4" stroke="{stroke}" stroke-width="1"/>
      <line x1="-18" y1="4"  x2="18" y2="4"  stroke="{stroke}" stroke-width="1"/>
      <line x1="0"   y1="-12" x2="0" y2="-4" stroke="{stroke}" stroke-width="1"/>
      <line x1="-9"  y1="-4" x2="-9" y2="4"  stroke="{stroke}" stroke-width="1"/>
      <line x1="9"   y1="-4" x2="9"  y2="4"  stroke="{stroke}" stroke-width="1"/>
      <line x1="-6"  y1="4"  x2="-6" y2="12" stroke="{stroke}" stroke-width="1"/>
      <line x1="6"   y1="4"  x2="6"  y2="12" stroke="{stroke}" stroke-width="1"/>
    """,
    # WAP — wireless waves
    "wap": """
      <circle cx="0" cy="4" r="5" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <path d="M-8,-4 Q0,-14 8,-4"  fill="none" stroke="{stroke}" stroke-width="1.5"/>
      <path d="M-14,-9 Q0,-24 14,-9" fill="none" stroke="{stroke}" stroke-width="1.5"/>
      <line x1="0" y1="-1" x2="0" y2="9" stroke="{stroke}" stroke-width="1.5"/>
    """,
    # Server — rack unit
    "server": """
      <rect x="-16" y="-14" width="32" height="10" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <rect x="-16" y="-2"  width="32" height="10" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <rect x="-16" y="10"  width="32" height="10" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <circle cx="10" cy="-9" r="2" fill="{stroke}"/>
      <circle cx="10" cy="3"  r="2" fill="{stroke}"/>
      <circle cx="10" cy="15" r="2" fill="{stroke}"/>
    """,
    # Workstation — monitor + base
    "workstation": """
      <rect x="-15" y="-14" width="30" height="20" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <rect x="-15" y="-14" width="30" height="20" rx="2"
            fill="none" stroke="{stroke}" stroke-width="1.5"/>
      <rect x="-4" y="7" width="8" height="4" fill="{fill}" stroke="{stroke}" stroke-width="1"/>
      <line x1="-8" y1="11" x2="8" y2="11" stroke="{stroke}" stroke-width="1.5"/>
    """,
    # Mobile — phone outline
    "mobile": """
      <rect x="-8" y="-16" width="16" height="28" rx="3"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <circle cx="0" cy="9" r="2" fill="{stroke}"/>
      <line x1="-3" y1="-13" x2="3" y2="-13" stroke="{stroke}" stroke-width="1.5"
            stroke-linecap="round"/>
    """,
    # IoT — chip/board
    "iot": """
      <rect x="-12" y="-12" width="24" height="24" rx="2"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
      <rect x="-6" y="-6" width="12" height="12" rx="1"
            fill="none" stroke="{stroke}" stroke-width="1"/>
      <line x1="-12" y1="-6"  x2="-16" y2="-6"  stroke="{stroke}" stroke-width="1.5"/>
      <line x1="-12" y1="0"   x2="-16" y2="0"   stroke="{stroke}" stroke-width="1.5"/>
      <line x1="-12" y1="6"   x2="-16" y2="6"   stroke="{stroke}" stroke-width="1.5"/>
      <line x1="12"  y1="-6"  x2="16"  y2="-6"  stroke="{stroke}" stroke-width="1.5"/>
      <line x1="12"  y1="0"   x2="16"  y2="0"   stroke="{stroke}" stroke-width="1.5"/>
      <line x1="12"  y1="6"   x2="16"  y2="6"   stroke="{stroke}" stroke-width="1.5"/>
    """,
    # Unknown — cloud
    "unknown": """
      <path d="M-14,6 Q-16,-4 -6,-8 Q-4,-16 8,-12 Q14,-16 16,-6 Q20,-4 16,6 Z"
            fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>
    """,
}

_COLORS = {
    "router":      ("#f38ba8", "#ff8fa3"),
    "switch":      ("#f38ba8", "#ff8fa3"),
    "firewall":    ("#f38ba8", "#ff8fa3"),
    "wap":         ("#f38ba8", "#ff8fa3"),
    "server":      ("#89b4fa", "#a0c4ff"),
    "workstation": ("#a6e3a1", "#b8f0b4"),
    "mobile":      ("#cba6f7", "#dbb8ff"),
    "iot":         ("#fab387", "#ffc49e"),
    "unknown":     ("#6c7086", "#888899"),
}

_SUBNET_COLORS = [
    "rgba(137,180,250,0.06)", "rgba(166,227,161,0.06)",
    "rgba(250,179,135,0.06)", "rgba(203,166,247,0.06)",
    "rgba(243,188,114,0.06)",
]

def _symbol_key(device_class: str, device_subclass: str) -> str:
    sub = (device_subclass or "").lower()
    dc  = (device_class  or "unknown").lower()
    if sub in ("router",): return "router"
    if sub in ("switch",): return "switch"
    if sub in ("firewall",): return "firewall"
    if sub in ("wap", "ap"): return "wap"
    if dc == "network":  return "router"
    if dc == "server":   return "server"
    if dc == "mobile":   return "mobile"
    if dc == "iot":      return "iot"
    if dc == "workstation": return "workstation"
    return "unknown"

def _host_to_dict(h) -> dict:
    if isinstance(h, dict): return h
    return {k: getattr(h, k, "") for k in
            ("ip","hostname","os_name","device_class","device_subclass",
             "open_ports","services","cves","mac","mac_vendor")}

def _subnet_of(ip: str) -> str:
    try:    return str(ipaddress.ip_interface(f"{ip}/24").network)
    except: return "unknown"

def _build_graph(hosts: list) -> tuple[list, list, list]:
    host_dicts = [_host_to_dict(h) for h in hosts]
    subnets: dict[str, list] = {}
    for h in host_dicts:
        subnets.setdefault(_subnet_of(h["ip"]), []).append(h)

    nodes, edges, subnet_boxes = [], [], []
    node_ids = {}

    CANVAS_W   = 1600
    MARGIN     = 100
    ROW_H      = 200
    COL_W      = 220
    subnet_x   = MARGIN

    def sort_key(h):
        return {"network":0,"server":1,"workstation":2,"iot":3,"mobile":4}.get(
            h.get("device_class","unknown"), 5)

    for sn_idx, (subnet, members) in enumerate(subnets.items()):
        members.sort(key=sort_key)
        gateways    = [h for h in members if h.get("device_class") == "network"]
        servers     = [h for h in members if h.get("device_class") == "server"]
        others      = [h for h in members
                       if h.get("device_class") not in ("network","server")]

        cols = max(3, min(6, len(members)))
        sn_top = 80

        # Gateways — top centre
        gw_start_x = subnet_x + (COL_W * cols) // 2 - (len(gateways) * 160) // 2
        for i, h in enumerate(gateways):
            nid = len(nodes)
            node_ids[h["ip"]] = nid
            nodes.append(_make_node(nid, h, gw_start_x + i * 160, sn_top + 40, subnet, sn_idx))

        # Servers — rightmost column
        srv_x = subnet_x + COL_W * (cols - 1) + COL_W // 2
        for i, h in enumerate(servers):
            nid = len(nodes)
            node_ids[h["ip"]] = nid
            nodes.append(_make_node(nid, h, srv_x, sn_top + 40 + i * ROW_H, subnet, sn_idx))

        # Others — grid in centre
        for i, h in enumerate(others):
            col = i % (cols - 1)
            row = i // (cols - 1)
            nx  = subnet_x + col * COL_W + COL_W // 2
            ny  = sn_top + ROW_H + row * ROW_H
            nid = len(nodes)
            node_ids[h["ip"]] = nid
            nodes.append(_make_node(nid, h, nx, ny, subnet, sn_idx))

        # Edges
        gw_ids  = [node_ids[h["ip"]] for h in gateways if h["ip"] in node_ids]
        all_ids = [node_ids[h["ip"]] for h in members  if h["ip"] in node_ids]
        if gw_ids:
            for mid in all_ids:
                if mid not in gw_ids:
                    edges.append({"from": gw_ids[0], "to": mid})
        elif len(all_ids) > 1:
            for mid in all_ids[1:]:
                edges.append({"from": all_ids[0], "to": mid})

        # Subnet bounding box
        sn_nodes = [n for n in nodes if n.get("subnet") == subnet]
        if sn_nodes:
            xs = [n["x"] for n in sn_nodes]
            ys = [n["y"] for n in sn_nodes]
            subnet_boxes.append({
                "label": subnet, "sn_idx": sn_idx,
                "x": min(xs)-70, "y": min(ys)-60,
                "w": max(xs)-min(xs)+180, "h": max(ys)-min(ys)+180,
                "color": _SUBNET_COLORS[sn_idx % len(_SUBNET_COLORS)],
            })

        subnet_x += COL_W * cols + MARGIN

    # Compute label side: LEFT if node is in right half of canvas, RIGHT otherwise
    if nodes:
        max_x = max(n["x"] for n in nodes)
        for n in nodes:
            n["label_side"] = "left" if n["x"] > max_x * 0.55 else "right"

    return nodes, edges, subnet_boxes

def _make_node(nid, h, x, y, subnet, sn_idx):
    dc      = h.get("device_class",  "unknown")
    ds      = h.get("device_subclass","")
    sym     = _symbol_key(dc, ds)
    fill, stroke = _COLORS.get(sym, ("#6c7086","#888899"))
    ports   = h.get("open_ports", [])[:8]
    svc     = h.get("services", {})
    cve_cnt = len(h.get("cves", []))

    port_labels = []
    for p in ports:
        name = ""
        if isinstance(svc, dict) and p in svc:
            s = svc[p]
            name = (s.get("name","") if isinstance(s,dict) else "")
        port_labels.append(f"{p}" + (f" {name}" if name else ""))

    return {
        "id": nid, "ip": h.get("ip",""),
        "hostname": h.get("hostname","") or h.get("ip",""),
        "os": h.get("os_name",""),
        "device_class": dc, "device_subclass": ds,
        "symbol": sym, "fill": fill, "stroke": stroke,
        "ports": port_labels, "cve_count": cve_cnt,
        "mac": h.get("mac",""), "vendor": h.get("mac_vendor",""),
        "subnet": subnet, "x": x, "y": y,
        "label_side": "right",   # overwritten after layout
    }

def _build_symbol_defs(nodes: list) -> str:
    """Build SVG <defs> with one symbol per unique (sym, fill, stroke) combo."""
    seen = set()
    defs = ["<defs>"]
    for n in nodes:
        key = (n["symbol"], n["fill"], n["stroke"])
        if key in seen: continue
        seen.add(key)
        sym_id = f"sym_{n['symbol']}_{n['fill'].strip('#')}_{n['stroke'].strip('#')}"
        path   = _SYMBOLS.get(n["symbol"], _SYMBOLS["unknown"])
        path   = path.replace("{fill}", n["fill"]).replace("{stroke}", n["stroke"])
        defs.append(f'<symbol id="{sym_id}" viewBox="-22 -22 44 44">{path}</symbol>')
    defs.append("</defs>")
    return "\n".join(defs)

def generate_diagram(hosts: list, output_path=None,
                     scan_result_dir: Optional[str] = None,
                     fenrir_callback_port: int = 0) -> str:
    if not hosts:
        return "<html><body style='background:#1e1e2e;color:#cdd6f4'><p>No hosts.</p></body></html>"

    nodes, edges, subnet_boxes = _build_graph(hosts)
    nodes_j   = json.dumps(nodes)
    edges_j   = json.dumps(edges)
    subnets_j = json.dumps(subnet_boxes)
    result_dir_j = json.dumps(scan_result_dir or "")
    cb_port_j    = json.dumps(fenrir_callback_port)

    sym_defs  = _build_symbol_defs(nodes)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fenrir — Network Topology</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ background:#1e1e2e; color:#cdd6f4;
       font-family:'Segoe UI',Helvetica,sans-serif; overflow:hidden }}
#toolbar {{ position:fixed; top:0; left:0; right:0; height:42px;
            background:#181825; border-bottom:1px solid #313244;
            display:flex; align-items:center; padding:0 14px; gap:10px; z-index:100 }}
#toolbar h1 {{ font-size:14px; color:#89b4fa; font-weight:600 }}
.tbtn {{ background:#313244; color:#cdd6f4; border:1px solid #45475a;
         padding:3px 11px; border-radius:4px; cursor:pointer; font-size:12px }}
.tbtn:hover {{ background:#45475a }}
#stats {{ margin-left:auto; font-size:11px; color:#6c7086 }}
#wrap {{ position:fixed; top:42px; left:0; right:0; bottom:0; overflow:hidden }}
svg {{ cursor:grab; width:100%; height:100% }}
svg.grabbing {{ cursor:grabbing }}
.node-sym {{ cursor:pointer; transition:filter .15s }}
.node-sym:hover {{ filter:brightness(1.3) drop-shadow(0 0 6px #89b4fa) }}
.label-ip {{ font:bold 11px 'Segoe UI',sans-serif; fill:#cdd6f4 }}
.label-host {{ font:10px 'Segoe UI',sans-serif; fill:#a6e3a1 }}
.label-os   {{ font:9px 'Segoe UI',sans-serif;  fill:#f9e2af }}
.label-port {{ font:9px monospace;               fill:#fab387 }}
.label-cve  {{ font:bold 10px 'Segoe UI',sans-serif; fill:#f38ba8;
               cursor:pointer; text-decoration:underline }}
.edge {{ stroke:#45475a; stroke-width:1.5; fill:none;
         stroke-opacity:0.6 }}
.subnet-box {{ fill-opacity:1; stroke-width:1.5; stroke-opacity:0.4 }}
.subnet-lbl {{ font:bold 11px 'Segoe UI',sans-serif; fill-opacity:0.5 }}
#tooltip {{ position:fixed; background:#181825; border:1px solid #45475a;
            border-radius:6px; padding:9px 13px; font-size:12px;
            line-height:1.7; pointer-events:none; display:none;
            z-index:200; max-width:260px }}
#legend {{ position:fixed; bottom:14px; left:14px; background:#181825ee;
           border:1px solid #313244; border-radius:6px;
           padding:8px 13px; font-size:11px; line-height:2 }}
#legend h3 {{ color:#89b4fa; font-size:11px; margin-bottom:2px }}
.ld {{ display:flex; align-items:center; gap:6px }}
.lsym {{ width:22px; height:22px }}
</style>
</head>
<body>
<div id="toolbar">
  <h1>⬡ Fenrir — Network Topology</h1>
  <button class="tbtn" onclick="fitAll()">⤢ Fit all</button>
  <button class="tbtn" onclick="resetZoom()">⊙ Reset</button>
  <button class="tbtn" onclick="exportSVG()">↓ SVG</button>
  <span id="stats"></span>
</div>
<div id="wrap">
<svg id="svg" xmlns="http://www.w3.org/2000/svg">
{sym_defs}
<g id="world">
  <g id="subnet-layer"></g>
  <g id="edge-layer"></g>
  <g id="node-layer"></g>
</g>
</svg>
</div>
<div id="tooltip"></div>
<div id="legend">
  <h3>Symbols</h3>
  <div class="ld"><svg class="lsym" viewBox="-22 -22 44 44">{_SYMBOLS["router"].replace("{fill}","#f38ba8").replace("{stroke}","#ff8fa3")}</svg> Router / Switch / FW</div>
  <div class="ld"><svg class="lsym" viewBox="-22 -22 44 44">{_SYMBOLS["server"].replace("{fill}","#89b4fa").replace("{stroke}","#a0c4ff")}</svg> Server</div>
  <div class="ld"><svg class="lsym" viewBox="-22 -22 44 44">{_SYMBOLS["workstation"].replace("{fill}","#a6e3a1").replace("{stroke}","#b8f0b4")}</svg> Workstation</div>
  <div class="ld"><svg class="lsym" viewBox="-22 -22 44 44">{_SYMBOLS["iot"].replace("{fill}","#fab387").replace("{stroke}","#ffc49e")}</svg> IoT</div>
  <div class="ld"><svg class="lsym" viewBox="-22 -22 44 44">{_SYMBOLS["mobile"].replace("{fill}","#cba6f7").replace("{stroke}","#dbb8ff")}</svg> Mobile</div>
</div>
<script>
const NODES      = {nodes_j};
const EDGES      = {edges_j};
const SUBNETS    = {subnets_j};
const RESULT_DIR = {result_dir_j};
const CB_PORT    = {cb_port_j};

const svg   = document.getElementById('svg');
const world = document.getElementById('world');
const tip   = document.getElementById('tooltip');
let vx=0, vy=0, vscale=1;
let dragging=false, dragOrigin=null, viewOrigin=null;

// ── Build SVG ─────────────────────────────────────────────────────────────────
function build() {{
  const sLayer = document.getElementById('subnet-layer');
  const eLayer = document.getElementById('edge-layer');
  const nLayer = document.getElementById('node-layer');

  // Subnets
  SUBNETS.forEach(s => {{
    const r = svgEl('rect', {{
      x:s.x, y:s.y, width:s.w, height:s.h, rx:12,
      class:'subnet-box', fill:s.color, stroke:'#89b4fa'
    }});
    const lbl = svgEl('text', {{
      x:s.x+10, y:s.y+18, class:'subnet-lbl', fill:'#89b4fa'
    }});
    lbl.textContent = s.label;
    sLayer.appendChild(r);
    sLayer.appendChild(lbl);
  }});

  // Edges
  EDGES.forEach(e => {{
    const a = NODES[e.from], b = NODES[e.to];
    if (!a||!b) return;
    eLayer.appendChild(svgEl('line', {{
      x1:a.x, y1:a.y, x2:b.x, y2:b.y, class:'edge'
    }}));
  }});

  // Nodes
  NODES.forEach(n => {{
    const g = svgEl('g', {{transform:`translate(${{n.x}},${{n.y}})`}});

    // Symbol (use defined symbol)
    const symId = `sym_${{n.symbol}}_${{n.fill.slice(1)}}_${{n.stroke.slice(1)}}`;
    const use = svgEl('use', {{
      href:`#${{symId}}`, x:-22, y:-22, width:44, height:44,
      class:'node-sym', 'data-id':n.id
    }});
    use.addEventListener('click', () => openDevice(n));
    use.addEventListener('mouseenter', (ev) => showTip(n, ev));
    use.addEventListener('mouseleave', hideTip);
    g.appendChild(use);

    // CVE badge (top-right of symbol)
    if (n.cve_count > 0) {{
      const bc = svgEl('circle', {{cx:16, cy:-16, r:9, fill:'#f38ba8'}});
      const bt = svgEl('text', {{
        x:16, y:-12, 'text-anchor':'middle',
        style:'font:bold 8px sans-serif;fill:#1e1e2e'
      }});
      bt.textContent = n.cve_count;
      bc.style.cursor = 'pointer';
      bt.style.cursor = 'pointer';
      bc.addEventListener('click', ()=>openDevice(n));
      bt.addEventListener('click', ()=>openDevice(n));
      g.appendChild(bc);
      g.appendChild(bt);
    }}

    // Labels — RIGHT or LEFT of symbol
    const side  = n.label_side === 'left' ? -1 : 1;
    const lx    = side * 28;
    const anchor = side > 0 ? 'start' : 'end';
    let ly = -14;

    const addLabel = (txt, cls, dy=13) => {{
      if (!txt) return;
      const t = svgEl('text', {{
        x:lx, y:ly, 'text-anchor':anchor, class:cls
      }});
      t.textContent = txt;
      g.appendChild(t);
      ly += dy;
    }};

    addLabel(n.ip,                         'label-ip',   13);
    addLabel(n.hostname !== n.ip
             ? n.hostname.substring(0,22)
             : '',                          'label-host', 12);
    addLabel(n.os ? n.os.substring(0,20) : '', 'label-os', 11);
    n.ports.slice(0,5).forEach(p => addLabel(p, 'label-port', 11));

    if (n.cve_count > 0) {{
      const t = svgEl('text', {{
        x:lx, y:ly, 'text-anchor':anchor, class:'label-cve'
      }});
      t.textContent = `CVE: ${{n.cve_count}}`;
      t.addEventListener('click', ()=>openDevice(n));
      g.appendChild(t);
    }}

    nLayer.appendChild(g);
  }});

  document.getElementById('stats').textContent =
    `${{NODES.length}} hosts  ·  ${{EDGES.length}} links`;
  fitAll();
}}

// ── SVG helpers ───────────────────────────────────────────────────────────────
function svgEl(tag, attrs) {{
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k,v] of Object.entries(attrs)) el.setAttribute(k,v);
  return el;
}}

// ── View transform ────────────────────────────────────────────────────────────
function applyTransform() {{
  world.setAttribute('transform',
    `translate(${{vx}},${{vy}}) scale(${{vscale}})`);
}}

function fitAll() {{
  if (!NODES.length) return;
  const rect = svg.getBoundingClientRect();
  const xs=NODES.map(n=>n.x), ys=NODES.map(n=>n.y);
  const minX=Math.min(...xs)-80, maxX=Math.max(...xs)+120;
  const minY=Math.min(...ys)-80, maxY=Math.max(...ys)+120;
  const rangeX=maxX-minX, rangeY=maxY-minY;
  vscale = Math.min((rect.width-40)/rangeX, (rect.height-40)/rangeY, 2);
  vx = (rect.width  - rangeX*vscale)/2 - minX*vscale;
  vy = (rect.height - rangeY*vscale)/2 - minY*vscale;
  applyTransform();
}}

function resetZoom() {{ vx=0; vy=0; vscale=1; applyTransform(); }}

// ── Pan & zoom ────────────────────────────────────────────────────────────────
svg.addEventListener('mousedown', e => {{
  dragging=true; svg.classList.add('grabbing');
  dragOrigin=[e.clientX,e.clientY]; viewOrigin=[vx,vy];
}});
window.addEventListener('mousemove', e => {{
  if (!dragging) return;
  vx=viewOrigin[0]+(e.clientX-dragOrigin[0]);
  vy=viewOrigin[1]+(e.clientY-dragOrigin[1]);
  applyTransform();
}});
window.addEventListener('mouseup', ()=>{{
  dragging=false; svg.classList.remove('grabbing');
}});
svg.addEventListener('wheel', e => {{
  e.preventDefault();
  const f=e.deltaY<0?1.12:0.89;
  const rect=svg.getBoundingClientRect();
  const mx=e.clientX-rect.left, my=e.clientY-rect.top;
  vx=mx-(mx-vx)*f; vy=my-(my-vy)*f; vscale*=f;
  vscale=Math.max(0.08,Math.min(vscale,6));
  applyTransform();
}},{{passive:false}});

// ── Tooltip ───────────────────────────────────────────────────────────────────
function showTip(n, ev) {{
  const ports = n.ports.length
    ? `<div style="color:#fab387">Ports: ${{n.ports.join('  ')}}</div>` : '';
  const cveRow = n.cve_count > 0
    ? `<div style="color:#f38ba8;font-weight:bold;cursor:pointer"
         onclick="openDevice(NODES[${{n.id}}])">CVE: ${{n.cve_count}} — click to view</div>` : '';
  tip.innerHTML = `
    <div style="color:#89b4fa;font-weight:bold;font-size:13px">${{n.ip}}</div>
    ${{n.hostname!==n.ip?`<div style="color:#a6e3a1">${{n.hostname}}</div>`:''}}
    ${{n.os?`<div style="color:#f9e2af">${{n.os}}</div>`:''}}
    <div style="color:#6c7086">${{n.device_class}}${{n.device_subclass?' / '+n.device_subclass:''}}</div>
    ${{n.vendor?`<div style="color:#6c7086">Vendor: ${{n.vendor}}</div>`:''}}
    ${{ports}}${{cveRow}}
    <div style="color:#6c7086;font-size:10px;margin-top:4px">Click to open in Fenrir</div>
  `;
  tip.style.display='block';
  tip.style.left=(ev.clientX+14)+'px';
  tip.style.top =(ev.clientY+14)+'px';
}}
function hideTip() {{ tip.style.display='none'; }}

// ── Open device in Fenrir ─────────────────────────────────────────────────────
function openDevice(n) {{
  if (CB_PORT) {{
    fetch(`http://127.0.0.1:${{CB_PORT}}/open?ip=${{encodeURIComponent(n.ip)}}`)
      .catch(()=>{{}});
  }}
}}

// ── Export ───────────────────────────────────────────────────────────────────
function exportSVG() {{
  const blob = new Blob([svg.outerHTML], {{type:'image/svg+xml'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fenrir_topology.svg';
  a.click();
}}

build();
window.addEventListener('resize', fitAll);
</script>
</body></html>"""

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
        log.info(f"[diagram] Topology written: {output_path}")
    return html
