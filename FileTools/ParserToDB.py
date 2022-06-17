import json
import getpass
import mysql.connector

mydb = mysql.connector.connect (
    host="localhost",
    user="root",
    password=getpass.getpass("Database Password: "),
    database="MalwareData"
)
tableName = "meta_data"

def ParseFile (fileName):
    data = ""
    skipFirstChar = True
    skipFirstFind = True
    with open(fileName, "r") as f:
        while chunk := f.read(1):
            if skipFirstChar:
                skipFirstChar = False
                continue

            data += chunk
            if data[-7:] == '{"_id":':
                if skipFirstFind:
                    skipFirstFind = False
                else:
                    ProcLine (data[0:-8])
                    data = '{"_id":'
    ProcLine (data[0:-2])

def ProcLine (data):
    jsonObj = json.loads(data)
    saveData = (
        jsonObj["_id"]["$oid"],
        jsonObj["md5"],
        jsonObj["sha256"],
        jsonObj["crc32"],
        jsonObj["adler32"],
        jsonObj["ssdeep"],
        jsonObj["headBytes"],
        jsonObj["tailBytes"],
        int(jsonObj["size"]),
        jsonObj["fileType"] if jsonObj["fileType"] is not None else "",
        jsonObj["mimeType"] if jsonObj["mimeType"] is not None else "",
        jsonObj["fileExtension"] if jsonObj["fileExtension"] is not None else "",
        json.dumps(jsonObj["exif"]) if jsonObj["exif"] != [] else '{}',
        jsonObj["vt"]
    )
    InsertDB(saveData)

def InsertDB (data):
    try:
        sql = f"INSERT INTO {tableName} VALUES {data};"
        cursorloc = mydb.cursor()
        cursorloc.execute(sql)
        mydb.commit()
    except:
        print (f"{data[0]} Failed")

def Main ():
    x = input ("Enter JSON file to parse: ")
    ParseFile (x)

if __name__ == "__main__":
    Main ()
