import os
from PIL import Image
import numpy as np

width_table=[(10,94),(30,192),(60,384),(100,768),(200,1152),(500,1536),(1000,2304)]

path = "/home/ryan/MalFiles/Safe/"
name = "npp.8.4.2.Installer.x64.exe"
filepath = path + name

filesize = int(round(os.stat(filepath).st_size/1024))
print (filesize)

image_width = 1
for width in width_table:
    if width[0] < filesize:
        image_width = width[1]

image_array = []
with open(filepath, "rb") as f:
    while byte := f.read(image_width):
        image_array.append(list(byte))

image_array[-1] += [0 for x in range(image_width-len(image_array[-1]))]
color_array = [[tuple(y[x:x+3]) for x in range(0, image_width, 3)] for y in image_array]

h = len(color_array)
w = int(image_width/3)
arr = np.zeros([h, w, 3], dtype=np.uint8)
for i in range(h):
    for j in range(w):
        arr[i,j] = color_array[i][j]
out = Image.fromarray(arr)
out.save(name+"color.png")
out2 = out.convert("L")
out2.save(name+"bw.png")
