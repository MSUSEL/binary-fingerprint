import re
import pefile

FILE_NAME = "/home/ryan/MalFiles/PEFiles/ShinoLocker.bin"
OUT_NAME = "Saved"

count = 0
with open(FILE_NAME, "rb") as f:
    read_file = f.read()
    png = rb"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A[\s\S]*?\x49\x45\x4E\x44"
    jpg = rb"\xFF\xD8\xFF[\s\S]*?\xFF\xD9"
    gif = rb"\x00\x00\x3B[\s\S]*?\x47\x49\x46\x38\x39\x61"
    ico = rb"\x00\x00\x01\x00[\s\S]*?\xf6\x87\x01\x77"
    for img in re.findall(png, read_file):
        with open(f"{OUT_NAME}{count}.png", "wb") as g:
            g.write(img)
        count += 1
    for img in re.findall(jpg, read_file):
        with open(f"{OUT_NAME}{count}.jpg", "wb") as g:
            g.write(img)
        count += 1
    for img in re.findall(gif, read_file):
        with open(f"{OUT_NAME}{count}.gif", "wb") as g:
            g.write(img)
        count += 1
    # for img in re.findall(ico, read_file):
        # with open(f"{OUT_NAME}{count}.ico", "wb") as g:
            # g.write(img)
        # count += 1
    print (f"Extracted {count} images")
