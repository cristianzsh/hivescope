"""
Renderers:
    render_text produces a plain-text report
    render_html produces a HTML report
"""

import datetime
import html as _html

from .const import TOOL_NAME, VERSION

UTC = datetime.timezone.utc


# Plain text
def _wrap_cols(headers, rows):
    cols = len(headers)
    widths = [len(str(h)) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i]) if i < len(r) else ""))
    return widths


def render_text(summary, sections):
    out = []
    out.append("=" * 78)
    out.append("%s %s" % (TOOL_NAME, VERSION))
    out.append("Windows registry forensic report")
    out.append("=" * 78)
    out.append("")
    for sec in sections:
        out.append(sec.title)
        out.append("=" * max(len(sec.title), 3))
        for el in sec.elements:
            kind = el[0]
            if kind == "kv":
                pairs = [(k, v) for (k, v) in el[1] if v not in ("", None)]
                width = max([len(str(k)) for k, _ in pairs] + [1])
                for k, v in pairs:
                    out.append("  %-*s : %s" % (width, k, v))
            elif kind == "sub":
                out.append("")
                out.append("  --- %s ---" % el[1])
            elif kind == "path":
                out.append("    Source key: %s" % el[1])
            elif kind == "paths":
                out.append("    Source keys:")
                for p in el[1]:
                    out.append("      - %s" % p)
            elif kind == "text":
                out.append("  %s" % el[1])
            elif kind == "note":
                out.append("  (%s)" % el[1])
            elif kind == "list":
                for it in el[1]:
                    out.append("    - %s" % it)
            elif kind == "table":
                headers, rows = el[1], el[2]
                if not rows:
                    out.append("    (no rows)")
                    continue
                widths = _wrap_cols(headers, rows)
                out.append(("  " + " | ".join(
                    "%-*s" % (widths[i], headers[i])
                    for i in range(len(headers)))).rstrip())
                out.append("  " + "-+-".join(
                    "-" * widths[i] for i in range(len(headers))))
                for r in rows:
                    cells = []
                    for i in range(len(headers)):
                        val = str(r[i]) if i < len(r) else ""
                        cells.append("%-*s" % (widths[i], val))
                    out.append(("  " + " | ".join(cells)).rstrip())
        out.append("")
        out.append("=" * 78)
        out.append("")
    return "\n".join(out)


# HTML
_HTML_CSS = """
:root{
  --bg:#2e3440; --panel:#3b4252; --panel2:#434c5e; --edge:#4c566a;
  --fg:#eceff4; --muted:#d8dee9; --accent:#88c0d0; --accent2:#a3be8c;
  --mark:#ebcb8b; --markfg:#2e3440; --key:#81a1c1;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
/* scrollbars */
html{scrollbar-width:thin;scrollbar-color:var(--edge) var(--bg)}
::-webkit-scrollbar{width:12px;height:12px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--edge);border-radius:8px;
  border:3px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
::-webkit-scrollbar-corner{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.5 "Segoe UI",Roboto,Helvetica,Arial,sans-serif}
code,.mono{font-family:"Cascadia Code",Consolas,"Courier New",monospace}
header{position:sticky;top:0;z-index:20;background:var(--panel);
  border-bottom:1px solid var(--edge);padding:12px 18px;
  display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header h1{font-size:16px;margin:0;color:var(--accent)}
header .meta{color:var(--muted);font-size:12px}
#q{flex:1;min-width:220px;background:var(--panel2);border:1px solid var(--edge);
  color:var(--fg);padding:8px 10px;border-radius:8px;font-size:13px}
#q:focus{outline:none;border-color:var(--accent)}
#count{color:var(--muted);font-size:12px;white-space:nowrap}
.layout{display:flex;align-items:flex-start}
nav{position:sticky;top:57px;align-self:flex-start;width:230px;flex:0 0 230px;
  padding:14px 10px;max-height:calc(100vh - 57px);overflow:auto;
  border-right:1px solid var(--edge)}
nav a{display:block;color:var(--muted);text-decoration:none;padding:5px 8px;
  border-radius:6px;font-size:13px;border-left:2px solid transparent}
nav a:hover{background:var(--panel2);color:var(--fg)}
nav a.active{background:var(--panel2);color:var(--accent);font-weight:600;
  border-left-color:var(--accent)}
main{flex:1;min-width:0;padding:18px 22px;max-width:1200px}
section{background:var(--panel);border:1px solid var(--edge);border-radius:12px;
  margin:0 0 18px;padding:14px 16px;scroll-margin-top:70px}
section h2{margin:0 0 10px;font-size:16px;color:var(--accent2);
  border-bottom:1px solid var(--edge);padding-bottom:8px}
h3.sub{margin:16px 0 4px;font-size:13px;color:var(--accent);
  text-transform:uppercase;letter-spacing:.04em}
.srckey{font-family:"Cascadia Code",Consolas,monospace;font-size:12px;
  color:var(--key);background:#2e3440;border-left:2px solid #5e81ac;
  padding:2px 8px;margin:3px 0 7px;border-radius:0 6px 6px 0;
  word-break:break-all}
.srckeys{margin:3px 0 7px}
.srckeys .srckey{margin:2px 0}
.kv{display:grid;grid-template-columns:230px 1fr;gap:2px 14px}
.kv .k{color:var(--muted)}
.kv .v{color:var(--fg);word-break:break-word}
ul.list{margin:4px 0;padding-left:20px}
ul.list li{word-break:break-word}
table{border-collapse:collapse;width:100%;margin:6px 0 4px;font-size:13px}
th,td{border:1px solid var(--edge);padding:5px 8px;text-align:left;
  vertical-align:top;word-break:break-word}
th{background:var(--panel2);color:var(--muted);position:sticky;top:57px}
tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.note{color:var(--muted);font-style:italic;margin:6px 0}
.summary .kv{grid-template-columns:200px 1fr;font-size:15px}
.summary{border-color:var(--accent)}
mark{background:var(--mark);color:var(--markfg);padding:0 1px;border-radius:2px}
.hidden{display:none !important}
footer{color:var(--muted);font-size:12px;padding:10px 22px 40px}
"""

_HTML_JS = """
(function(){
  var q=document.getElementById('q');
  var count=document.getElementById('count');
  var items=[].slice.call(document.querySelectorAll('.s'));
  items.forEach(function(el){el.setAttribute('data-o',el.innerHTML);});
  function esc(s){return s.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&');}
  function run(){
    var term=q.value.trim();
    var low=term.toLowerCase();
    var re= term? new RegExp('('+esc(term)+')','ig') : null;
    var shown=0;
    items.forEach(function(el){
      var t=el.getAttribute('data-t')||'';
      var match = !term || t.indexOf(low)>=0;
      el.classList.toggle('hidden', !match);
      if(match) shown++;
      var o=el.getAttribute('data-o');
      if(re && match){ el.innerHTML=o.replace(re,'<mark>$1</mark>'); }
      else { el.innerHTML=o; }
    });
    document.querySelectorAll('section').forEach(function(sec){
      var vis=sec.querySelectorAll('.s:not(.hidden)').length;
      sec.classList.toggle('hidden', !!term && vis===0);
    });
    count.textContent= term? (shown+' matches') : '';
    spy();
  }
  var tmr=null;
  q.addEventListener('input',function(){clearTimeout(tmr);tmr=setTimeout(run,120);});
  q.addEventListener('keydown',function(e){if(e.key==='Escape'){q.value='';run();}});

  // side-nav active highlight
  var sections=[].slice.call(document.querySelectorAll('main section'));
  var links={};
  [].slice.call(document.querySelectorAll('nav a')).forEach(function(a){
    var id=a.getAttribute('href').slice(1);
    links[id]=a;
    a.addEventListener('click',function(){setActive(id);});
  });
  function setActive(id){
    for(var k in links){ links[k].classList.toggle('active', k===id); }
  }
  function spy(){
    var top=80, cur=null, i;
    for(i=0;i<sections.length;i++){
      var s=sections[i];
      if(s.classList.contains('hidden')) continue;
      if(s.getBoundingClientRect().top<=top){ cur=s.id; }
    }
    if(!cur){
      for(i=0;i<sections.length;i++){
        if(!sections[i].classList.contains('hidden')){ cur=sections[i].id; break; }
      }
    }
    setActive(cur);
  }
  window.addEventListener('scroll',spy,{passive:true});
  window.addEventListener('resize',spy);
  spy();
})();
"""


def _h(s):
    return _html.escape("" if s is None else str(s))


def _lc(s):
    return _html.escape(("" if s is None else str(s))).lower()


def render_html(summary, sections):
    parts = []
    parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width,"
                 "initial-scale=1'>")
    parts.append("<title>%s - %s</title>" % (_h(TOOL_NAME), _h(summary["name"])))
    parts.append("<style>%s</style></head><body>" % _HTML_CSS)
    parts.append("<header><h1>%s</h1>" % _h(TOOL_NAME))
    parts.append("<span class='meta'>%s &middot; %s &middot; generated %s</span>"
                 % (_h(summary["name"]), _h(summary["os"]),
                    _h(fmt_now())))
    parts.append("<input id='q' type='search' placeholder='Search the whole "
                 "report&hellip;  (Esc clears)'>")
    parts.append("<span id='count'></span></header>")
    parts.append("<div class='layout'><nav>")
    for sec in sections:
        parts.append("<a href='#%s'>%s</a>" % (_h(sec.key), _h(sec.title)))
    parts.append("</nav><main>")

    for sec in sections:
        cls = "summary" if sec.key == "summary" else ""
        parts.append("<section id='%s' class='%s'>" % (_h(sec.key), cls))
        parts.append("<h2>%s</h2>" % _h(sec.title))
        for el in sec.elements:
            kind = el[0]
            if kind == "kv":
                parts.append("<div class='kv'>")
                for k, v in el[1]:
                    if v == "" or v is None:
                        continue
                    parts.append(
                        "<div class='k'>%s</div>"
                        "<div class='v s' data-t='%s'>%s</div>"
                        % (_h(k), _lc(v), _h(v)))
                parts.append("</div>")
            elif kind == "sub":
                parts.append("<h3 class='sub'>%s</h3>" % _h(el[1]))
            elif kind == "path":
                parts.append("<div class='srckey s' data-t='%s'>%s</div>"
                             % (_lc(el[1]), _h(el[1])))
            elif kind == "paths":
                parts.append("<div class='srckeys'>")
                for p in el[1]:
                    parts.append("<div class='srckey s' data-t='%s'>%s</div>"
                                 % (_lc(p), _h(p)))
                parts.append("</div>")
            elif kind == "text":
                parts.append("<p class='s' data-t='%s'>%s</p>"
                             % (_lc(el[1]), _h(el[1])))
            elif kind == "note":
                parts.append("<p class='note'>%s</p>" % _h(el[1]))
            elif kind == "list":
                parts.append("<ul class='list'>")
                for it in el[1]:
                    parts.append("<li class='s mono' data-t='%s'>%s</li>"
                                 % (_lc(it), _h(it)))
                parts.append("</ul>")
            elif kind == "table":
                headers, rows = el[1], el[2]
                parts.append("<table><thead><tr>")
                for hh in headers:
                    parts.append("<th>%s</th>" % _h(hh))
                parts.append("</tr></thead><tbody>")
                for r in rows:
                    rowtext = " ".join(str(c) for c in r)
                    parts.append("<tr class='s' data-t='%s'>" % _lc(rowtext))
                    for i in range(len(headers)):
                        val = r[i] if i < len(r) else ""
                        parts.append("<td class='mono'>%s</td>" % _h(val))
                    parts.append("</tr>")
                parts.append("</tbody></table>")
        parts.append("</section>")

    parts.append("</main></div>")
    parts.append("<footer>Generated by %s %s. Hash-slot status reflects the "
                 "SAM V-structure length fields; extract actual hashes with a "
                 "dedicated tool if needed.</footer>"
                 % (_h(TOOL_NAME), _h(VERSION)))
    parts.append("<script>%s</script></body></html>" % _HTML_JS)
    return "".join(parts)


def fmt_now():
    return datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# JSON
def _json_safe(v):
    """Coerce a value to something json.dump can serialise."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, datetime.datetime):
        return v.isoformat()
    return str(v)


def _element_to_dict(el):
    kind = el[0]
    if kind == "kv":
        return {"type": "kv",
                "pairs": [[str(k), _json_safe(val)] for k, val in el[1]]}
    if kind == "table":
        return {"type": "table",
                "headers": [str(h) for h in el[1]],
                "rows": [[_json_safe(c) for c in r] for r in el[2]]}
    if kind in ("list", "paths"):
        return {"type": kind, "items": [_json_safe(i) for i in el[1]]}
    # sub / path / text / note
    return {"type": kind, "text": _json_safe(el[1])}


def render_json(summary, sections, indent=2):
    """Return a structured JSON document of the whole report."""
    import json
    doc = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_utc": datetime.datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "summary": {str(k): _json_safe(v) for k, v in (summary or {}).items()},
        "sections": [
            {"key": sec.key, "title": sec.title,
             "elements": [_element_to_dict(el) for el in sec.elements]}
            for sec in sections
        ],
    }
    return json.dumps(doc, indent=indent, ensure_ascii=False)
