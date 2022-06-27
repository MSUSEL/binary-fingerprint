import math
from PIL import Image as im
import numpy as np
import pefile
import imagehash
import string

ALPHABET = string.ascii_letters

file = "/home/ryan/MalFiles/Safe/Wireshark-win32-3.6.6.exe"

pe = pefile.PE(file)
raw = pe.write()

dic = {}
for i in pe.DIRECTORY_ENTRY_IMPORT:
    dllName = i.dll.decode()
    dic.setdefault(dllName[0], [])
    dic[dllName[0]].append(dllName)

    for j in i.imports:
        if j.name is not None:
            apiName = j.name.decode()
            dic.setdefault(apiName[0], [])
            dic[apiName[0]].append(apiName)

# Calculate the max length
maxLen = 0
for i in dic:
    count = 0
    for j in dic[i]:
        count += len(j)

    maxLen = count if count > maxLen else maxLen


# Add into image
imageArr = []
for i in ALPHABET:
    arr = dic.get(i, [])
    arr.sort()
    count = maxLen - sum([len(x) for x in arr])
    items = len(arr)-1
    strArr = "\x00"*maxLen
    if items > 0:
        include = math.floor(count/items)
        strArr = ('\x00'*include).join(arr)
        strArr += "\x00"*(maxLen-len(strArr))

    imageArr.append([ord(x) for x in strArr])

# Save the data and calculates the hashes
np_array = np.array(imageArr)
data = im.fromarray((np_array * 255).astype(np.uint8))
imgHash = imagehash.average_hash(data)
print (f"imphash: {pe.get_imphash()}")
print (f"Import Hash: {imgHash}")
data.save("TestImports.png")
