import sys
import pickle
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Show which clusters file is in')
    parser.add_argument("-l", "--lists", dest="l", type=str, nargs='+', required=True,
            help='One or more pickled cluster list files')
    parser.add_argument("-s", "--hash", dest="hash", type=str, required=True,
            help='File hash to search for')

    args = parser.parse_args()

    lists = []

    for i in args.l:
        with open(i, "rb") as f:
            x = pickle.load(f)
            for count, j in enumerate(x):
                if args.hash in j:
                    print (f"Cluster {count} in {i}")
                    print (f"Contains {len(j)} other entries")
                    print ()
                    lists.append(set(j))
