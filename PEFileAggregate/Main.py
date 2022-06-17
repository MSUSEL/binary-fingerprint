import hashlib
import pefile
import magic
import ssdeep
# import peutils

def MetaData (file):
    # fp = open(file, "rb")
    pe = pefile.PE(file, fast_load=True)
    raw = pe.write()
    print(f"{file:~^100}")
    print(f"    File Type: {magic.from_file(file)}")
    print(f"    MIME Type: {magic.from_file(file, mime=True)}")
    print(f"    Size:      {len(raw)}")
    print(f"    Entropy:   {round(pe.sections[0].entropy_H(raw),3)}")
    print()
    print(f"    MD5:       {hashlib.md5(raw).hexdigest()}")
    print(f"    SHA-256:   {hashlib.sha256(raw).hexdigest()}")
    print(f"    SSDEEP:    {ssdeep.hash_from_file(file)}")
    # for section in pe.sections:
        # print("%s entropy: %f (Min=0.0, Max=8.0)" % (SectionNameToString(section.Name), section.get_entropy()))

MetaData("/home/ryan/MalFiles/PEFiles/remcosrat")
