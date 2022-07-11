with open("a.txt", "r") as f:
    while item := f.readline():

        # 8 9 a or b
        if (item[0] == "8" or item[0] == "9" or item[0] == "a" or item[0]=="b"):
            print (f"/mnt/sda/vol1/{item[0:3]}/{item}", end='')

        # c d e or f
        elif (item[0] == "c" or item[0] == "d" or item[0] == "e" or item[0]=="f"):
            print (f"/mnt/sdb/vol2/{item[0:3]}/{item}", end='')

        # 4 5 6 or 7
        elif (item[0] == "4" or item[0] == "5" or item[0] == "6" or item[0]=="7"):
            print (f"/mnt/sdc/vol3/{item[0:3]}/{item}", end='')

        # 0 1 2 or 3
        elif (item[0] == "0" or item[0] == "1" or item[0] == "2" or item[0]=="3"):
            print (f"/mnt/sdd/vol4/{item[0:3]}/{item}", end='')
