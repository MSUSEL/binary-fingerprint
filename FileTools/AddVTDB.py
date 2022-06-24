import getpass
import vt
import mysql.connector

mydb = mysql.connector.connect (
    host="localhost",
    user="root",
    password=getpass.getpass("Database Password: "),
    database="MalwareData"
)
tableName = "sample_pe"
sqlStatement = f"SELECT _id, md5 FROM {tableName} limit 1900, 100;"
cursorloc = mydb.cursor()
cursorloc.execute(sqlStatement)

client = vt.Client(getpass.getpass("VirusTotal API: "))

for i in cursorloc.fetchall():
    file = client.get_object(f"/files/{i[1]}")

    # Find the VT classification
    classif = ""
    try:
        classif = file.get("popular_threat_classification")["suggested_threat_label"]
    except:
        classif = ""

    # Find possible packers identified
    packers = file.get("packers")
    pack = ""
    if packers is not None:
        (x, y), *rest = packers.items()
        pack = y


    # Update the database
    sqlInsert = f"update {tableName} set packers='{pack}', classif='{classif}' where _id='{i[0]}';"

    try:
        cursorloc.execute(sqlInsert)
        mydb.commit()
    except:
        print ("ERROR: ", end='')

    print (f"{i[0]}: {pack} {classif}")

client.close()
