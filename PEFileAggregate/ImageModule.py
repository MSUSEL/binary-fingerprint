import math
import imagehash
import pefile
import numpy as np
from PIL import Image as im

SAVE_PATH = "./images/shino/"
WIDTH_TABLE=[(10,32), (30,64), (60,128), (100,256), (200,384), (500,512), (1000,768), (1001,1024)]

class ImageData:
    '''Data object that houses information about images'''

    def __init__ (self, file, size, save=False):
        pe = pefile.PE(file)
        self.file = file
        self.pe = pe
        self.hashes = self.partImage(save)
        # self.hashes.update(self.fullImage(size, save))

    def returnHash (self, name):
        return self.hashes[name]

    def fullImage (self, size, save):
        if size/1024 > 20000:
            return {"full": 0}

        width = 1
        for x in WIDTH_TABLE:
            if x[0] < size:
                width = x[1]

        array = []
        with open(self.file, "rb") as f:
            while byte := f.read(width):
                array.append(list(byte))
        while (len(array[-1]) < width):
            array[-1].append(0)

        np_array = np.array(array)
        data = im.fromarray((np_array * 255).astype(np.uint8))
        if save:
            data.save(f"{SAVE_PATH}full.png")

        return {"full":imagehash.average_hash(data)}

    def partImage (self, save):
        hashes = {}
        for i in self.pe.sections:
            name = i.Name.decode().rstrip(chr(0))
            bincode = self.pe.get_data(i.PointerToRawData, i.SizeOfRawData)

            if len(bincode) == 0:
                hashes[name] = 0
                continue

            width = math.ceil(math.sqrt(len(bincode)))
            bincode += b"\x00"*(width**2 - len(bincode))

            array = [[bincode[x] for x in range(y*width, (y+1)*width)] for y in range(width)]
            np_array = np.array(array)
            data = im.fromarray((np_array * 255).astype(np.uint8))

            if save:
                data.save(f"{SAVE_PATH}{name}.png")

            hashes[name] = imagehash.average_hash(data)
        return hashes

    def importImage (self, save):
        return False
