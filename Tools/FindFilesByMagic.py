import os
import argparse
import magic

def matchType (nameList, fType, path):
    if any(x.lower() in fType.lower() for x in nameList):
        print (f"{path}\n\t{fType}\n")
        return 1
    return 0

def findFiles (root, nameList, recur):
    count, total = 0, 0

    if recur:
        for directory, sublist, filelist in os.walk(root):
            for file in filelist:
                fType = magic.from_file(os.path.join(directory, file))
                count += matchType (nameList, fType, os.path.join(directory, file))
                total += 1
    else:
        for file in os.listdir(root):
            if os.path.isfile(os.path.join(root, file)):
                fType = magic.from_file(os.path.join(root, file))
                count += matchType (nameList, fType, os.path.join(root, file))
                total += 1

    print (f"Found {count}/{total} matching files")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find files that have a specified magic')
    parser.add_argument('-d', '--directory', dest='dir', type=str, required=True,
            help='Directory to scan')
    parser.add_argument('-r', '--recursively', dest='rec', action='store_true',
            help='Recursively scan the directory')
    parser.add_argument('-f', '--file', dest='file', type=str, nargs='+', required=True,
            help='List of file types to scan')

    args = parser.parse_args()

    findFiles (args.dir, args.file, args.rec)
