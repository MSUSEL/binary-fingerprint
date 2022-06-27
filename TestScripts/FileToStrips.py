import os
from PIL import Image, ImageEnhance
import numpy as np

width_table=[(10,99),(30,189),(60,399),(100,756),(200,1155),(500,1533),(1000,2373)]

path = "/home/ryan/MalFiles/PEFiles/"
name = "ShinoLocker.bin"
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

image_array[-1] += [b"\x00" for x in range(image_width-len(image_array[-1]))]
color_array = [[tuple(y[x:x+3]) for x in range(0, image_width, 3)] for y in image_array]

np_array = np.array(color_array)
data = Image.fromarray(np_array, mode="RGB")
data2 = ImageEnhance.Brightness(data)
data2.enhance(3.0).save(name+"banded.png")
