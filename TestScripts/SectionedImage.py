import os
# import imagehash
import pefile
import numpy as np
from PIL import Image as im

SAVE_PATH = "./client/"
# WIDTH_TABLE=[(10,32), (30,64), (60,128), (100,256), (200,384), (500,512), (1000,768), (1001,1024)]
FILE = "/home/ryan/MalFiles/PEFiles/Client.bin"
LOW_THRESHOLD = 3 * 512
SAVE = True

def fullImage (width):
    array = []
    with open(FILE, "rb") as f:
        while byte := f.read(width):
            array.append(list(byte))

    array[-1] += [0 for x in range(width-len(array[-1]))]

    np_array = np.array(array)
    data = im.fromarray((np_array * 255).astype(np.uint8))

    if SAVE:
        data.save(f"{SAVE_PATH}full.png")

def partImage (width):
    pe = pefile.PE(FILE, fast_load=True)
    with open(FILE, "rb") as f:
        for i in pe.sections:
            name = i.Name.decode().rstrip(chr(0))
            start = i.PointerToRawData
            size = i.SizeOfRawData
            if size < LOW_THRESHOLD:
                continue

            f.seek(start)
            bincode = f.read(size)
            bincode += b"\x00"*(width-(len(bincode)%width))
            array = [[bincode[x] for x in range(y*width, (y+1)*width)] for y in range(int(len(bincode)/width))]

            np_array = np.array(array)
            data = im.fromarray((np_array * 255).astype(np.uint8))

            if SAVE:
                data.save(f"{SAVE_PATH}a{name}.png")

if __name__ == "__main__":
    os.makedirs(SAVE_PATH, exist_ok=True)

    size = os.path.getsize(FILE)
    width = 512
    # width = 1
    # for x in WIDTH_TABLE:
        # if x[0] < size/1024:
            # width = x[1]

    partImage(width)
    fullImage(width)
