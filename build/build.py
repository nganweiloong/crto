#!/usr/bin/env python3
"""Build CRTO-Playbook.md and a self-contained, searchable CRTO-Playbook.html."""
from __future__ import annotations

import html
import re
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
MD_OUT = ROOT / "CRTO-Playbook.md"
HTML_OUT = ROOT / "CRTO-Playbook.html"


def concat_sources() -> str:
    parts = sorted(SRC.glob("*.md"))
    if not parts:
        raise SystemExit("No source files found in src/")
    chunks = []
    for p in parts:
        text = p.read_text(encoding="utf-8").strip()
        chunks.append(text)
    return "\n\n".join(chunks) + "\n"


def build_toc(tokens, level=0):
    if not tokens:
        return ""
    items = []
    for t in tokens:
        name = html.escape(re.sub(r"<[^>]+>", "", t["name"]))
        children = build_toc(t.get("children", []), level + 1)
        cls = f' class="lvl-{t["level"]}"'
        sub = f"\n<ul>{children}</ul>\n" if children else ""
        items.append(f'<li{cls}><a href="#{t["id"]}">{name}</a>{sub}</li>')
    return "\n".join(items)


def main() -> None:
    md_text = concat_sources()
    MD_OUT.write_text(md_text, encoding="utf-8")

    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
        extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}},
    )
    body = md.convert(md_text)
    toc_html = build_toc(md.toc_tokens)

    template = r"""<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRTO I — Red Team Operator Playbook</title>
<style>
:root{
  --bg:#0f1115; --bg2:#161a21; --fg:#e6e9ef; --muted:#9aa4b2; --line:#2a3140;
  --accent:#ff6b35; --accent2:#4ea1ff; --code-bg:#11151c; --mark:#ffd166;
  --sidebar:#12161d; --shadow:0 8px 30px rgba(0,0,0,.35);
}
@media (prefers-color-scheme: light){
  :root[data-theme="auto"]{
    --bg:#fbfbfd; --bg2:#ffffff; --fg:#171a1f; --muted:#5b6472; --line:#e3e6ec;
    --accent:#d9480f; --accent2:#1c6dd0; --code-bg:#f4f5f8; --mark:#ffe08a;
    --sidebar:#f4f5f8; --shadow:0 8px 30px rgba(0,0,0,.10);
  }
}
:root[data-theme="light"]{
  --bg:#fbfbfd; --bg2:#ffffff; --fg:#171a1f; --muted:#5b6472; --line:#e3e6ec;
  --accent:#d9480f; --accent2:#1c6dd0; --code-bg:#f4f5f8; --mark:#ffe08a;
  --sidebar:#f4f5f8; --shadow:0 8px 30px rgba(0,0,0,.10);
}
:root[data-theme="dark"]{
  --bg:#0f1115; --bg2:#161a21; --fg:#e6e9ef; --muted:#9aa4b2; --line:#2a3140;
  --accent:#ff6b35; --accent2:#4ea1ff; --code-bg:#11151c; --mark:#ffd166;
  --sidebar:#12161d; --shadow:0 8px 30px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent2);text-decoration:none}
a:hover{text-decoration:underline}
#layout{display:grid;grid-template-columns:320px minmax(0,1fr);min-height:100vh}
#sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:var(--sidebar);border-right:1px solid var(--line);padding:18px 14px 40px}
#sidebar h1{font-size:15px;margin:0 0 4px;letter-spacing:.02em}
#sidebar .sub{color:var(--muted);font-size:12px;margin-bottom:14px}
#search{width:100%;padding:9px 11px;border-radius:9px;border:1px solid var(--line);background:var(--bg2);color:var(--fg);font-size:13px;margin-bottom:10px}
#search:focus{outline:2px solid var(--accent2);outline-offset:1px}
.toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.toolbar button{cursor:pointer;background:var(--bg2);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px}
.toolbar button:hover{border-color:var(--accent2)}
#toc ul{list-style:none;margin:0;padding-left:12px}
#toc>ul{padding-left:0}
#toc li{margin:1px 0}
#toc li.lvl-1>a{font-weight:700;color:var(--fg);font-size:13px}
#toc li.lvl-2>a{font-size:12.5px}
#toc li.lvl-3>a{font-size:12px;color:var(--muted)}
#toc a{display:block;padding:3px 7px;border-radius:6px}
#toc a:hover{background:var(--bg2);text-decoration:none}
#toc a.active{background:var(--bg2);box-shadow:inset 3px 0 0 var(--accent)}
main{padding:34px clamp(16px,4vw,64px) 90px;max-width:1080px;width:100%}
.content h1,.content h2,.content h3{scroll-margin-top:14px}
.content h1{font-size:30px;line-height:1.2;margin:0 0 10px;padding-bottom:10px;border-bottom:2px solid var(--accent)}
.content h2{font-size:22px;margin:34px 0 10px;padding-top:8px;border-top:1px solid var(--line);cursor:pointer;position:relative}
.content h2::after{content:"▾";position:absolute;right:4px;top:10px;color:var(--muted);font-size:14px;transition:transform .15s}
section.sec.collapsed>h2::after{transform:rotate(-90deg)}
.content h3{font-size:17px;margin:24px 0 8px;color:var(--accent2)}
.content h4{font-size:15px;margin:18px 0 6px}
.content p{margin:8px 0}
.content ul,.content ol{margin:8px 0 8px 22px;padding:0}
.content li{margin:3px 0}
.content blockquote{margin:14px 0;padding:10px 16px;border-left:4px solid var(--accent);background:var(--bg2);border-radius:0 8px 8px 0;color:var(--muted)}
.content code{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:.9em;background:var(--code-bg);padding:1px 5px;border-radius:4px;border:1px solid var(--line)}
.content pre{background:var(--code-bg);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow:auto;margin:12px 0;box-shadow:none}
.content pre code{background:none;border:0;padding:0;font-size:12.8px;line-height:1.55;white-space:pre}
.content table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13.5px;display:block;overflow-x:auto}
.content th,.content td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
.content th{background:var(--bg2);font-weight:650;white-space:nowrap}
.content tr:nth-child(even) td{background:color-mix(in srgb,var(--bg2) 55%,transparent)}
.content hr{border:0;border-top:1px solid var(--line);margin:26px 0}
.content img{max-width:100%}
.content mark{background:var(--mark);color:#111;border-radius:2px}
section.sec.collapsed>*:not(h2){display:none}
section.sec.collapsed{border-bottom:1px solid var(--line);margin-bottom:8px}
#top{position:fixed;right:18px;bottom:18px;width:40px;height:40px;border-radius:50%;border:1px solid var(--line);background:var(--bg2);color:var(--fg);cursor:pointer;display:none;box-shadow:var(--shadow)}
#menu{display:none}
@media (max-width:900px){
  #layout{grid-template-columns:1fr}
  #sidebar{position:fixed;z-index:50;left:0;top:0;width:86%;max-width:340px;transform:translateX(-102%);transition:transform .2s;box-shadow:var(--shadow)}
  #sidebar.open{transform:none}
  #menu{display:inline-block;position:fixed;right:16px;top:14px;z-index:60;background:var(--bg2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 12px;cursor:pointer}
  main{padding-top:60px}
}
.print-cover{display:none}
@page{size:A4;margin:14mm 12mm}
@media print{
  #sidebar,#menu,#top,#search,.toolbar{display:none!important}
  #layout{display:block}
  main{max-width:none;padding:0}
  section.sec.collapsed>*:not(h2){display:block!important}
  body{background:#fff;color:#000;font-size:10.5pt}
  .print-cover{display:block;page-break-after:always;padding:40mm 0 0;text-align:center}
  .print-cover h1{font-size:28pt;border:0;margin:0 0 8pt}
  .print-cover p{color:#333;font-size:11pt}
  .content h1{font-size:21pt;break-before:page;page-break-before:always}
  .content h1:first-of-type{break-before:auto;page-break-before:auto}
  .content h2{font-size:15pt;break-after:avoid;page-break-after:avoid;cursor:default}
  .content h2::after{display:none}
  .content h3{font-size:12pt;break-after:avoid;page-break-after:avoid}
  .content h4{break-after:avoid}
  .content pre,.content table,.content blockquote{break-inside:avoid;page-break-inside:avoid}
  .content tr{break-inside:avoid;page-break-inside:avoid}
  .content table{display:table;width:100%;font-size:9pt}
  .content pre{white-space:pre-wrap;word-break:break-word;font-size:8.6pt;border:1px solid #bbb}
  .content code{border:1px solid #ddd;background:#f6f6f6}
  .content a{color:#000;text-decoration:none}
}
</style>
</head>
<body>
<button id="menu" aria-label="Toggle navigation">☰ Menu</button>
<div id="layout">
  <aside id="sidebar">
    <h1>CRTO I — Playbook</h1>
    <div class="sub">Red Team Ops · exam-day reference</div>
    <input id="search" type="search" placeholder="Search sections, commands, tools…" autocomplete="off">
    <div class="toolbar">
      <button id="expandAll" type="button">Expand all</button>
      <button id="collapseAll" type="button">Collapse all</button>
      <button id="themeBtn" type="button">Theme</button>
    </div>
    <nav id="toc"><ul>__TOC__</ul></nav>
  </aside>
  <main>
    <div class="print-cover">
      <h1>CRTO I — Red Team Operator Playbook</h1>
      <p>Red Team Ops · Windows / Active Directory · Cobalt Strike</p>
      <p>Exam-day command reference, attack paths, and OPSEC</p>
      <p>Verify the current exam format before use. For authorized lab and exam use only.</p>
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
  // Wrap each h2 and its following content into a collapsible section.
  var children=Array.prototype.slice.call(content.children);
  var current=null;
  children.forEach(function(el){
    if(el.tagName==='H1'){
      current=null;
    } else if(el.tagName==='H2'){
      current=document.createElement('section');
      current.className='sec';
      content.insertBefore(current,el);
      current.appendChild(el);
    } else if(current){
      current.appendChild(el);
    }
  });
  var sections=Array.prototype.slice.call(document.querySelectorAll('section.sec'));
  sections.forEach(function(s){
    var h=s.querySelector('h2');
    if(!h)return;
    h.addEventListener('click',function(e){
      if(e.target.tagName==='A')return;
      s.classList.toggle('collapsed');
      try{localStorage.setItem('crto-collapse:'+h.id, s.classList.contains('collapsed')?'1':'0');}catch(e){}
    });
    try{
      if(localStorage.getItem('crto-collapse:'+h.id)==='1') s.classList.add('collapsed');
    }catch(e){}
  });
  document.getElementById('expandAll').onclick=function(){sections.forEach(function(s){s.classList.remove('collapsed');});};
  document.getElementById('collapseAll').onclick=function(){sections.forEach(function(s){s.classList.add('collapsed');});};

  // Search: filter sections by text content.
  var search=document.getElementById('search');
  search.addEventListener('input',function(){
    var q=search.value.trim().toLowerCase();
    sections.forEach(function(s){
      var match=!q||s.textContent.toLowerCase().indexOf(q)!==-1;
      s.style.display=match?'':'none';
      if(q&&match) s.classList.remove('collapsed');
    });
    // Also filter TOC links.
    var links=document.querySelectorAll('#toc a');
    links.forEach(function(a){
      var li=a.parentElement;
      var match=!q||a.textContent.toLowerCase().indexOf(q)!==-1;
      li.style.display=match?'':'none';
    });
  });

  // Theme toggle: auto -> dark -> light -> auto
  var root=document.documentElement;
  var btn=document.getElementById('themeBtn');
  var modes=['auto','dark','light'];
  var saved=null; try{saved=localStorage.getItem('crto-theme');}catch(e){}
  if(saved) root.setAttribute('data-theme',saved);
  btn.onclick=function(){
    var i=(modes.indexOf(root.getAttribute('data-theme')||'auto')+1)%modes.length;
    var m=modes[i]; root.setAttribute('data-theme',m);
    try{localStorage.setItem('crto-theme',m);}catch(e){}
    btn.textContent='Theme: '+m;
  };

  // Mobile menu
  var menu=document.getElementById('menu');
  var sidebar=document.getElementById('sidebar');
  menu.onclick=function(){sidebar.classList.toggle('open');};
  sidebar.addEventListener('click',function(e){
    if(e.target.tagName==='A' && window.innerWidth<=900) sidebar.classList.remove('open');
  });

  // Back to top
  var top=document.getElementById('top');
  window.addEventListener('scroll',function(){top.style.display=window.scrollY>600?'block':'none';});
  top.onclick=function(){window.scrollTo({top:0,behavior:'smooth'});};

  // Highlight active TOC entry
  var tocLinks=Array.prototype.slice.call(document.querySelectorAll('#toc a'));
  var byId={}; tocLinks.forEach(function(a){byId[a.getAttribute('href').slice(1)]=a;});
  var obs=new IntersectionObserver(function(entries){
    entries.forEach(function(en){
      var a=byId[en.target.id];
      if(!a)return;
      if(en.isIntersecting){
        tocLinks.forEach(function(x){x.classList.remove('active');});
        a.classList.add('active');
      }
    });
  },{rootMargin:'-10% 0px -80% 0px'});
  Array.prototype.forEach.call(document.querySelectorAll('h2[id],h3[id]'),function(h){obs.observe(h);});

  // Keyboard: "/" focuses search
  document.addEventListener('keydown',function(e){
    if(e.key==='/' && document.activeElement!==search){e.preventDefault();search.focus();}
    if(e.key==='Escape' && document.activeElement===search){search.value='';search.dispatchEvent(new Event('input'));search.blur();}
  });
})();
</script>
</body>
</html>
"""
    out = template.replace("__TOC__", toc_html).replace("__BODY__", body)
    HTML_OUT.write_text(out, encoding="utf-8")

    print(f"Wrote {MD_OUT} ({len(md_text):,} chars, {md_text.count(chr(10)):,} lines)")
    print(f"Wrote {HTML_OUT} ({len(out):,} chars)")


if __name__ == "__main__":
    main()
