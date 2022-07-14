import os
import time
import json
import argparse
import itertools
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from PIL import ImageChops, Image

def calcdiff(im1, im2, directory, f1, f2):
    im1 = Image.open(f"{directory}/{f1}/icos/{im1}")
    im2 = Image.open(f"{directory}/{f2}/icos/{im2}")
    try:
        dif = ImageChops.difference(im1, im2)
        return np.mean(np.array(dif))
    except Exception:
        return 99999

def constructMatrix (file, directory, threshold):
    dic = {}

    folderWithIcos = []
    for folder in os.listdir(directory):
        if len(os.listdir(f"{directory}/{folder}/icos")) > 0:
            folderWithIcos.append(folder)

    folderWithIcos = folderWithIcos[:100]
    while folder := folderWithIcos.pop(0):
        initIcos = os.listdir(f"{directory}/{folder}/icos")
        for cmpFld in folderWithIcos:
            cmpIcos = os.listdir(f"{directory}/{cmpFld}/icos")
            cmps = [calcdiff(a, b, directory, folder, cmpFld) for (a, b) in itertools.product(initIcos, cmpIcos)]
            if min(cmps) < threshold:
                # l1 = folder[:7]
                # l2 = cmpFld[:7]
                dic.setdefault(folder, [])
                dic[folder].append(cmpFld)
        if len(folderWithIcos) == 0:
            break

    g = nx.Graph(dic)
    for i in (g.subgraph(c) for c in nx.connected_components(g)):
        print (list(i))
    # nx.draw(g,with_labels=False)
    # plt.draw()
    # plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create matrix of similar things')
    parser.add_argument("-d", "--directory", dest="dir", type=str, required=True,
            help='directory to scan')
    parser.add_argument("-f", '--details', dest='det', type=str, required=True,
            help='detail file to load')
    parser.add_argument("-t", '--threshold', dest='thresh', type=int, default=2,
            help='comparison index')

    args = parser.parse_args()

    start = time.time()

    constructMatrix(args.det, args.dir, args.thresh)

    print (f"Finished in {time.time() - start} seconds")
