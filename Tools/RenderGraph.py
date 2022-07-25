import pickle
import argparse
import networkx as nx
import matplotlib.pyplot as plt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='View graph from pickled file')
    parser.add_argument("-f", "--file", dest='file', type=str, required=True,
            help='Pickled graph file')

    args = parser.parse_args()

    with open(args.file, "rb") as f:
        g = pickle.load(f)

    nx.draw(g, with_labels=False)
    plt.show()
