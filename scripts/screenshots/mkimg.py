# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Invented demo photos (landscapes drawn with Pillow) for the screenshot vault.
import sys, math
from PIL import Image, ImageDraw, ImageFilter
out = sys.argv[1]
def grad(w,h,c1,c2,horizon=0.55):
    im = Image.new("RGB",(w,h))
    px = im.load()
    for y in range(h):
        t=y/h
        for x in range(w):
            px[x,y]=tuple(int(c1[i]*(1-t)+c2[i]*t) for i in range(3))
    return im
def scene(name, sky1, sky2, ground, sun):
    im = grad(1200,800, sky1, sky2)
    d = ImageDraw.Draw(im)
    d.ellipse((860,120,1000,260), fill=sun)
    # hills
    for i,(off,col) in enumerate([(0,ground),(60,tuple(max(0,c-25) for c in ground)),(130,tuple(max(0,c-50) for c in ground))]):
        pts=[(0,800)]
        for x in range(0,1201,20):
            y=560+off+40*math.sin(x/180+i)+20*math.sin(x/70+i*2)
            pts.append((x,y))
        pts.append((1200,800))
        d.polygon(pts, fill=col)
    im = im.filter(ImageFilter.GaussianBlur(0.6))
    im.save(f"{out}/{name}.jpg", quality=86)
scene("forest", (60,110,170),(190,220,235),(44,120,70),(255,222,120))
scene("lake", (40,80,150),(160,200,230),(30,90,140),(255,240,200))
scene("sunset", (120,50,110),(250,150,80),(70,40,60),(255,200,90))
