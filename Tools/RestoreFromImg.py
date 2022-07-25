import argparse
import numpy as np
from PIL import Image as im

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Restore file from image')
    parser.add_argument('-f', '--file', dest='file', type=str, required=True,
            help='Image to restore back to file')
    parser.add_argument('-s', '--size', dest='size', type=int, required=True,
            help='Original size of file')
    parser.add_argument('-o', '--out', dest='out', type=str, default='restored',
            help='Output name')

    args = parser.parse_args()

    with open(args.out, "wb") as f:
        count = 0
        for i in np.array(im.open(args.file).getdata(), dtype=np.uint8):
            try:
                f.write(int(256-i).to_bytes(1, 'big'))
            except Exception:
                f.write(int(i).to_bytes(1, 'big'))

            count += 1
            if count >= args.size:
                break
