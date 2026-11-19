#!/usr/bin/env python3
"""Build CRTO-Mock-Exam.html from CRTO-Mock-Exam.md."""
from __future__ import annotations

import html
import re
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
MD_IN = ROOT / "CRTO-Mock-Exam.md"
HTML_OUT = ROOT / "CRTO-Mock-Exam.html"


def build_toc(tokens):
    items = []
    for t in tokens:
        name = html.escape(re.sub(r"<[^>]+>", "", t["name"]))
        children = build_toc(t.get("children", []))
        sub = f"\n<ul>{children}</ul>\n" if children else ""
        items.append(f'<li class="lvl-{t["level"]}"><a href="#{t["id"]}">{name}</a>{sub}</li>')
    return "\n".join(items)


def main() -> None:
    md_text = MD_IN.read_text(encoding="utf-8")
    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list", "md_in_html"],
        extension_configs={"toc": {"toc_depth": "2-3"}},
    )
    body = md.convert(md_text)
    toc_html = build_toc(md.toc_tokens)

    template = r"""<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRTO I — Mock Exam Walkthrough</title>
<style>
:root{--bg:#0f1115;--bg2:#161a21;--fg:#e6e9ef;--muted:#9aa4b2;--line:#2a3140;--accent:#ff6b35;--accent2:#4ea1ff;--code-bg:#11151c;--mark:#ffd166;--sidebar:#12161d;--shadow:0 8px 30px rgba(0,0,0,.35)}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{--bg:#fbfbfd;--bg2:#fff;--fg:#171a1f;--muted:#5b6472;--line:#e3e6ec;--accent:#d9480f;--accent2:#1c6dd0;--code-bg:#f4f5f8;--mark:#ffe08a;--sidebar:#f4f5f8;--shadow:0 8px 30px rgba(0,0,0,.10)}}
:root[data-theme="light"]{--bg:#fbfbfd;--bg2:#fff;--fg:#171a1f;--muted:#5b6472;--line:#e3e6ec;--accent:#d9480f;--accent2:#1c6dd0;--code-bg:#f4f5f8;--mark:#ffe08a;--sidebar:#f4f5f8;--shadow:0 8px 30px rgba(0,0,0,.10)}
:root[data-theme="dark"]{--bg:#0f1115;--bg2:#161a21;--fg:#e6e9ef;--muted:#9aa4b2;--line:#2a3140;--accent:#ff6b35;--accent2:#4ea1ff;--code-bg:#11151c;--mark:#ffd166;--sidebar:#12161d;--shadow:0 8px 30px rgba(0,0,0,.35)}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
#layout{display:grid;grid-template-columns:300px minmax(0,1fr);min-height:100vh}
#sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:var(--sidebar);border-right:1px solid var(--line);padding:18px 14px 40px}
#sidebar h1{font-size:15px;margin:0 0 4px}#sidebar .sub{color:var(--muted);font-size:12px;margin-bottom:14px}
#search{width:100%;padding:9px 11px;border-radius:9px;border:1px solid var(--line);background:var(--bg2);color:var(--fg);font-size:13px;margin-bottom:10px}
#search:focus{outline:2px solid var(--accent2);outline-offset:1px}
.toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.toolbar button{cursor:pointer;background:var(--bg2);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px}
.toolbar button:hover{border-color:var(--accent2)}
#toc ul{list-style:none;margin:0;padding-left:12px}#toc>ul{padding-left:0}
#toc li.lvl-2>a{font-size:12.5px}#toc li.lvl-3>a{font-size:12px;color:var(--muted)}
#toc a{display:block;padding:3px 7px;border-radius:6px}#toc a:hover{background:var(--bg2);text-decoration:none}
#toc a.active{background:var(--bg2);box-shadow:inset 3px 0 0 var(--accent)}
main{padding:34px clamp(16px,4vw,64px) 90px;max-width:980px;width:100%}
.content h1,.content h2,.content h3{scroll-margin-top:14px}
.content h1{font-size:29px;line-height:1.2;margin:0 0 10px;padding-bottom:10px;border-bottom:2px solid var(--accent)}
.content h2{font-size:22px;margin:34px 0 10px;padding-top:8px;border-top:1px solid var(--line);cursor:pointer;position:relative}
.content h2::after{content:"▾";position:absolute;right:4px;top:10px;color:var(--muted);font-size:14px;transition:transform .15s}
section.sec.collapsed>h2::after{transform:rotate(-90deg)}
.content h3{font-size:17px;margin:24px 0 8px;color:var(--accent2)}
.content p{margin:8px 0}.content ul,.content ol{margin:8px 0 8px 22px;padding:0}.content li{margin:3px 0}
.content blockquote{margin:14px 0;padding:10px 16px;border-left:4px solid var(--accent);background:var(--bg2);border-radius:0 8px 8px 0;color:var(--muted)}
.content code{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:.9em;background:var(--code-bg);padding:1px 5px;border-radius:4px;border:1px solid var(--line)}
.content pre{background:var(--code-bg);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:auto;margin:12px 0}
.content pre code{background:none;border:0;padding:0;font-size:12.8px;line-height:1.55;white-space:pre}
.content table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13.5px;display:block;overflow-x:auto}
.content th,.content td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
.content th{background:var(--bg2);font-weight:650;white-space:nowrap}
.content tr:nth-child(even) td{background:color-mix(in srgb,var(--bg2) 55%,transparent)}
.content hr{border:0;border-top:1px solid var(--line);margin:26px 0}
details{border:1px solid var(--line);border-radius:9px;padding:10px 15px;margin:14px 0;background:var(--bg2)}
summary{cursor:pointer;font-weight:650;color:var(--accent)}
details[open] summary{margin-bottom:8px}
section.sec.collapsed>*:not(h2){display:none}
section.sec.collapsed{border-bottom:1px solid var(--line);margin-bottom:8px}
#top{position:fixed;right:18px;bottom:18px;width:40px;height:40px;border-radius:50%;border:1px solid var(--line);background:var(--bg2);color:var(--fg);cursor:pointer;display:none;box-shadow:var(--shadow)}
#menu{display:none}
@media (max-width:900px){#layout{grid-template-columns:1fr}#sidebar{position:fixed;z-index:50;left:0;top:0;width:86%;max-width:340px;transform:translateX(-102%);transition:transform .2s;box-shadow:var(--shadow)}#sidebar.open{transform:none}#menu{display:inline-block;position:fixed;right:16px;top:14px;z-index:60;background:var(--bg2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 12px;cursor:pointer}main{padding-top:60px}}
.print-cover{display:none}
@page{size:A4;margin:14mm 12mm}
@media print{#sidebar,#menu,#top,#search,.toolbar{display:none!important}#layout{display:block}main{max-width:none;padding:0}section.sec.collapsed>*:not(h2){display:block!important}body{background:#fff;color:#000;font-size:10.5pt}.print-cover{display:block;page-break-after:always;padding:40mm 0 0;text-align:center}.print-cover h1{font-size:26pt;border:0;margin:0 0 8pt}.print-cover p{color:#333}.content h1{font-size:21pt;break-before:page;page-break-before:always}.content h1:first-of-type{break-before:auto;page-break-before:auto}.content h2{font-size:15pt;break-after:avoid;page-break-after:avoid;cursor:default}.content h2::after{display:none}.content h3{font-size:12pt;break-after:avoid}.content pre,.content table,.content blockquote,details{break-inside:avoid;page-break-inside:avoid}.content tr{break-inside:avoid}.content table{display:table;width:100%;font-size:9pt}.content pre{white-space:pre-wrap;word-break:break-word;font-size:8.6pt;border:1px solid #bbb}.content code{border:1px solid #ddd;background:#f6f6f6}.content a{color:#000;text-decoration:none}}
</style>
</head>
<body>
<button id="menu" aria-label="Toggle navigation">☰ Menu</button>
<div id="layout">
  <aside id="sidebar">
    <h1>CRTO I — Mock Exam</h1>
    <div class="sub">Walkthrough · decisions · OPSEC</div>
    <input id="search" type="search" placeholder="Search sections…" autocomplete="off">
    <div class="toolbar">
      <button id="expandAll" type="button">Expand all</button>
      <button id="collapseAll" type="button">Collapse all</button>
      <button id="themeBtn" type="button">Theme</button>
    </div>
    <nav id="toc"><ul>__TOC__</ul></nav>
  </aside>
  <main>
    <div class="print-cover">
      <h1>CRTO I — Mock Exam Walkthrough</h1>
      <p>Fictional training scenario — not the real exam</p>
      <p>Decision points, commands, OPSEC traps, self-scoring</p>
    </div>
    <article class="content" id="content">
__BODY__
    </article>
  </main>
</div>
<button id="top" title="Back to top">↑</button>
<script>
(function(){
  var content=document.getElementById('content');
  var children=Array.prototype.slice.call(content.children);
  var current=null;
  children.forEach(function(el){
    if(el.tagName==='H1'){current=null;}
    else if(el.tagName==='H2'){
      current=document.createElement('section');current.className='sec';
      content.insertBefore(current,el);current.appendChild(el);
    } else if(current){current.appendChild(el);}
  });
  var sections=Array.prototype.slice.call(document.querySelectorAll('section.sec'));
  sections.forEach(function(s){
    var h=s.querySelector('h2');if(!h)return;
    h.addEventListener('click',function(e){if(e.target.tagName==='A')return;s.classList.toggle('collapsed');try{localStorage.setItem('mock-collapse:'+h.id,s.classList.contains('collapsed')?'1':'0');}catch(e){}});
    try{if(localStorage.getItem('mock-collapse:'+h.id)==='1')s.classList.add('collapsed');}catch(e){}
  });
  document.getElementById('expandAll').onclick=function(){sections.forEach(function(s){s.classList.remove('collapsed');});};
  document.getElementById('collapseAll').onclick=function(){sections.forEach(function(s){s.classList.add('collapsed');});};
  var search=document.getElementById('search');
  search.addEventListener('input',function(){
    var q=search.value.trim().toLowerCase();
    sections.forEach(function(s){var m=!q||s.textContent.toLowerCase().indexOf(q)!==-1;s.style.display=m?'':'none';if(q&&m)s.classList.remove('collapsed');});
    document.querySelectorAll('#toc a').forEach(function(a){var m=!q||a.textContent.toLowerCase().indexOf(q)!==-1;a.parentElement.style.display=m?'':'none';});
  });
  var root=document.documentElement,btn=document.getElementById('themeBtn'),modes=['auto','dark','light'],saved=null;
  try{saved=localStorage.getItem('mock-theme');}catch(e){}
  if(saved)root.setAttribute('data-theme',saved);
  btn.onclick=function(){var i=(modes.indexOf(root.getAttribute('data-theme')||'auto')+1)%modes.length;var m=modes[i];root.setAttribute('data-theme',m);try{localStorage.setItem('mock-theme',m);}catch(e){}btn.textContent='Theme: '+m;};
  var menu=document.getElementById('menu'),sidebar=document.getElementById('sidebar');
  menu.onclick=function(){sidebar.classList.toggle('open');};
  sidebar.addEventListener('click',function(e){if(e.target.tagName==='A'&&window.innerWidth<=900)sidebar.classList.remove('open');});
  var top=document.getElementById('top');
  window.addEventListener('scroll',function(){top.style.display=window.scrollY>600?'block':'none';});
  top.onclick=function(){window.scrollTo({top:0,behavior:'smooth'});};
  document.addEventListener('keydown',function(e){if(e.key==='/'&&document.activeElement!==search){e.preventDefault();search.focus();}if(e.key==='Escape'&&document.activeElement===search){search.value='';search.dispatchEvent(new Event('input'));search.blur();}});
})();
</script>
</body>
</html>
"""
    out = template.replace("__TOC__", toc_html).replace("__BODY__", body)
    HTML_OUT.write_text(out, encoding="utf-8")
    print(f"Wrote {HTML_OUT} ({len(out):,} chars)")


if __name__ == "__main__":
    main()
