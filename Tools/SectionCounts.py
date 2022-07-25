import argparse
import json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='List all sections and counts')
    parser.add_argument("-f", "--file", dest="file", type=str, required=True,
            help='Detail file generated from SectionedImage.py')

    args = parser.parse_args()

    dic = {}
    with open(args.file, "r", encoding="utf-8") as f:
        while line := f.readline():
            for section in json.loads(line)["sections"]:
                dic.setdefault(section, 0)
                dic[section] += 1

    print ("Section Header Counts:")
    for i in dict(sorted(dic.items(), key=lambda item: item[1], reverse=True)):
        print (f"{i.strip():>10} - {dic[i]}")
