#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, math, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; A=ROOT/'assets'; MARK=A/'mark.svg'
ACCENT='#00e5a0'; BG='#09090b'; TEXT='#e2e8f0'; MUTED='#94a3b8'; DIM='#64748b'; PURPLE='#7c3aed'
MONO="'JetBrains Mono','JetBrainsMono Nerd Font',ui-monospace,SFMono-Regular,Menlo,monospace"
SANS="Inter,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
NAME='Agent Evidence Level'; LEAD='Agent Evidence '; TAG='Open standard for grading agent evidence'
FOOT='Apache 2.0 code  ·  maintained by PipeLab'
def inner():
 t=MARK.read_text(); v=re.search(r'viewBox="([^"]+)"',t); b=re.search(r'<svg[^>]*>(.*)</svg>',t,re.S)
 if not v or not b: raise SystemExit('invalid master mark')
 return v.group(1),b.group(1).strip()
def place(x,y,size):
 v,b=inner(); vx,vy,vw,vh=map(float,v.split()); s=size/max(vw,vh)
 return f'<g transform="translate({x} {y}) scale({s:.6f}) translate({-vx} {-vy})">{b}</g>'
def open_svg(w,h,label): return f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{label}">'
def particles(w,h):
 state=7; p=[]
 for _ in range(44):
  state=(state*1103515245+12345)%2**31; x=80+(state%1000)/1000*(w-160)
  state=(state*1103515245+12345)%2**31; y=40+(state%1000)/1000*(h-80); p.append((round(x,1),round(y,1)))
 out=[f'<g stroke="{ACCENT}" stroke-width="1">']
 for i,(x,y) in enumerate(p):
  for xx,yy in p[i+1:]:
   d=math.hypot(xx-x,yy-y)
   if d<150: out.append(f'<line x1="{x}" y1="{y}" x2="{xx}" y2="{yy}" opacity="{round(.16*(1-d/150),3)}"/>')
 out+=['</g>',f'<g fill="{ACCENT}" opacity=".5">']+[f'<circle cx="{x}" cy="{y}" r="1.6"/>' for x,y in p]+['</g>']; return ''.join(out)
def logo(): return open_svg(240,240,NAME+' logo')+place(24,24,192)+'</svg>\n'
def favicon(): return open_svg(64,64,NAME+' favicon')+f'<rect width="64" height="64" rx="14" fill="{BG}"/>'+place(10,10,44)+'</svg>\n'
def lockup():
 return open_svg(694,112,NAME+' logo lockup')+place(20,10,96)+f'<text x="140" y="70.42" font-family="{MONO}" font-size="46" font-weight="700" letter-spacing="-.02em" xml:space="preserve"><tspan fill="{TEXT}">{LEAD}</tspan><tspan fill="{ACCENT}">Level</tspan></text></svg>\n'
def stacked():
 return open_svg(540,252,NAME+' stacked logo')+place(204,26,132)+f'<text x="270" y="222" text-anchor="middle" font-family="{MONO}" font-size="40" font-weight="700" letter-spacing="-.02em" xml:space="preserve"><tspan fill="{TEXT}">{LEAD}</tspan><tspan fill="{ACCENT}">Level</tspan></text></svg>\n'
def social():
 w=1280;h=640
 s=open_svg(w,h,NAME+': '+TAG)+f'<defs><radialGradient id="teal" cx="30%" cy="20%" r="55%"><stop offset="0%" stop-color="{ACCENT}" stop-opacity=".22"/><stop offset="100%" stop-color="{ACCENT}" stop-opacity="0"/></radialGradient><radialGradient id="purple" cx="72%" cy="82%" r="55%"><stop offset="0%" stop-color="{PURPLE}" stop-opacity=".30"/><stop offset="100%" stop-color="{PURPLE}" stop-opacity="0"/></radialGradient></defs><rect width="{w}" height="{h}" fill="{BG}"/><rect width="{w}" height="{h}" fill="url(#teal)"/><rect width="{w}" height="{h}" fill="url(#purple)"/>'+particles(w,h)+place(104,174,264)
 s+=f'<text x="410" y="290" font-family="{MONO}" font-size="68" font-weight="700" letter-spacing="-.025em" xml:space="preserve"><tspan fill="{TEXT}">{LEAD}</tspan><tspan fill="{ACCENT}">Level</tspan></text><text x="414" y="348" font-family="{SANS}" font-size="27" fill="{MUTED}">{TAG}</text>'
 for i in range(5):
  x=414+i*102;s+=f'<rect x="{x}" y="393" width="88" height="42" rx="21" fill="{ACCENT}" fill-opacity=".10" stroke="{ACCENT}" stroke-opacity=".34"/><text x="{x+44}" y="420" text-anchor="middle" font-family="{MONO}" font-size="16" font-weight="600" fill="{ACCENT}">AEL-{i}</text>'
 return s+f'<text x="120" y="566" font-family="{MONO}" font-size="16" fill="{DIM}" letter-spacing=".07em">{FOOT}</text></svg>\n'
FILES={'ael-logo.svg':logo,'ael-favicon.svg':favicon,'ael-lockup.svg':lockup,'ael-lockup-stacked.svg':stacked,'social-preview.svg':social}
PNGS={'ael-logo-256.png':'ael-logo.svg','social-preview.png':'social-preview.svg'}
def stamp(path,src): return 'svg '+hashlib.sha256(src.read_bytes().replace(b'\r\n',b'\n')).hexdigest()+'\npng '+hashlib.sha256(path.read_bytes()).hexdigest()+'\n'
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--stamp-png',action='store_true');a=p.parse_args()
 if a.stamp_png:
  for png,svg in PNGS.items():(A/(png+'.source')).write_text(stamp(A/png,A/svg))
  return 0
 expected={A/n:f() for n,f in FILES.items()}
 if a.check:
  bad=[str(x.relative_to(ROOT)) for x,c in expected.items() if not x.exists() or x.read_text()!=c]
  for png,svg in PNGS.items():
   side=A/(png+'.source')
   if not (A/png).exists() or not side.exists() or side.read_text()!=stamp(A/png,A/svg):bad.append('assets/'+png)
  if bad: print('check-brand: FAIL - '+', '.join(bad),file=sys.stderr);return 1
  print(f'check-brand: OK ({len(FILES)} vectors and {len(PNGS)} rasters)');return 0
 for x,c in expected.items():x.write_text(c,newline='\n');print('wrote',x.relative_to(ROOT))
 return 0
if __name__=='__main__':sys.exit(main())
