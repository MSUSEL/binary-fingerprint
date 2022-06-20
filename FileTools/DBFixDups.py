import getpass
import mysql.connector

mydb = mysql.connector.connect (
    host="localhost",
    user="root",
    password=getpass.getpass("Database Password: "),
    database="MalwareData"
)
tableName = "meta_data"

def QueryDuplicates (count):
    deleted = 0
    inner = f"(SELECT * FROM {tableName} limit {count}) as firsts" if count > 0 else tableName

    # Get possible duplicates by checking MD5 hash
    sql = f"SELECT \
        md5, \
        GROUP_CONCAT(_id ORDER BY _id SEPARATOR ';') as duplicates \
        FROM {inner} \
        GROUP BY md5 \
        HAVING COUNT(*) > 1;"

    cursorloc = mydb.cursor()
    cursorloc.execute(sql)
    results = cursorloc.fetchall()

    # Loop through results
    for row in results:
        nonUniqueID = []
        uniqueRow = []

        # Get each ID to check and compare
        for _id in row[1].split(';'):
            query = f"SELECT * FROM {tableName} WHERE _id='{_id}';"
            cursorloc.execute(query)
            lineResult = cursorloc.fetchall()[0]

            if lineResult[1:] not in uniqueRow:
                uniqueRow.append(lineResult[1:])
            else:
                nonUniqueID.append(lineResult[0])

        # Remove Non Unique Rows
        for _id in nonUniqueID:
            remove = f"DELETE FROM {tableName} WHERE _id='{_id}';"
            deleted += 1
            # cursorloc.execute(remove)
            # mydb.commit()

    return deleted

def Main ():
    print(f"{QueryDuplicates(1000000)} Duplicate Records Deleted")

if __name__ == "__main__":
    Main ()
