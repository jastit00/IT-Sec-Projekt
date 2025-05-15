# we are again at it w/ python :D
#yessir https://www.google.com/search?client=firefox-b-d&sca_esv=4c75ca2344971d57&sxsrf=AHTn8zq4PAjEH8cHEdSwoBB2YA-bw8gQRw:1744306555911&q=tanzender+hund&udm=7&fbs=ABzOT_DDfJxgmsKFIwrWKcoyw2RfsHtJv_PUtkAwS8Lyd_zhMskbS4o26LY5umjWWVR1cvN4DvrJMcb7dDhNgS2eJFTxGH-3bvuc8s1gAw3J2sW2yZEhR0B-4sWg7k7XsoqEtk5QyJtH2f5IgFD54l4BtHHLdwI-KcDmUbrjKeLwxmD-oCKGhq7clYHugT0H92Jk8RmJ82dgILA9fYsJWUTPfoyxeBUbjA&sa=X&ved=2ahUKEwih1ZOlgM6MAxVDgP0HHSuLEocQtKgLegQILBAB&biw=1760&bih=868&dpr=1.09#fpstate=ive&vld=cid:0c1e0767,vid:OsfbSWuni54,st:0
from datetime import datetime
import csv
import pandas as pd

"""
things to cover w/in this program:
    - read an audit
    - filter the information we want and write it in a csv file (provisionary)
    - display the information in the "cleaned" file
fields interesting for us:
    - ["type","IP address", "audit user ID" ,"date", "command", "return state"]
"""

# we will use this later on:
def getInfo(recordType, content):
    # 2.1 write all the types we can find
    if recordType=="DAEMON_START":
        # every type is going to get a number that we are going to use for the information extraction
        # print("deamon started") -> uncomment for debugging
        # 2.2 return list w/ the info we could extract from that line
        # we get the line and take the second (index 1) filed that contains timestamp and id of audit; once we have the msg=audit( we split the string into timestamp and :id); we select the first element (the timestamp)
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        auid=content[6].replace("auid=",'')
        endStatus=content[10].replace("res=",'')
        return [recordType,"---",auid,dateTimestamp,"---",endStatus]
        
    elif recordType=="CONFIG_CHANGE":
        # print("configuration changed")
        dateTimestamp=float(content[1].replace("msg=audit(",'').split(":")[0])
        auid=content[6].replace("auid=",'')
        endStatus=content[7].replace("res=",'')
        return [recordType,"---",auid,datetime.fromtimestamp(dateTimestamp),"---",endStatus]
        
    elif recordType=="SYSCALL":
        # print("system call to kernel")
        # migth be interesting to add a field w/ what was done in the system call (compare: https://gist.github.com/Qoyyuum/39024aae1e3f15302b506faf802d508a)
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        auid=content[13].replace("auid=",'')
        return [recordType,"---","---",dateTimestamp,"---","---"]
        
    elif recordType=="SOCKADDR":
        # print("recording socket address")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        return [recordType,"---","---",dateTimestamp,"---","---"]
        
    elif recordType=="PROCTITLE":
        # print("command used to start process")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        # hexCommand=content[2].replace("proctitle=",'') -> in case we need to do it in several lines
        command=bytes.fromhex(content[2].replace("proctitle=",'')).decode('utf-8')
        return [recordType,"---","---",dateTimestamp,command,"---"]
        
    elif recordType=="ANOM_ABEND":
        # print("process terminated with error")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        auid=content[2].replace("auid=",'')
        endStatus=content[10].replace("res=",'')
        return [recordType,"---",auid,dateTimestamp,"---",endStatus]
        
    elif recordType=="USER_LOGIN":
        # print("user tried to log in")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        auid=content[4].replace("auid=",'')
        ipAddress=content[10].replace("addr=",'')
        endStatus=content[11].replace("res=",'')
        return [recordType,ipAddress,auid,dateTimestamp,"---",endStatus]
        
    elif recordType=="USYS_CONFIG":
        # print("changes in user config done")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        auid=content[4].replace("auid=",'')
        ipAddress=content[13].replace("addr=",'')
        endStatus=content[15].replace("res=",'')
        return [recordType,"---", "---",dateTimestamp,"---",endStatus]
        
    else:
        # print("unkown entry")
        dateTimestamp=(datetime.fromtimestamp(float(content[1].replace("msg=audit(",'').split(":")[0]))).strftime("%d/%m/%Y, %H:%M:%S")
        return [recordType,"---", "---",dateTimestamp,"---","---"]
    
# 1. read the audit
try:
    with open("brute_force_example.log") as file:
        print("file read\n---")
        print("we are going to start reading and picking out the data we want\n---")
        rows=[]
        # 2. filter information
        for i in file.readlines():
            # the readlines will give us a list with all the lines in it -> easy to iterate over it
            rows.append(getInfo(i.split()[0].replace("type=",''),i.split()))
        # print(rows)
        fields=["type","IP address", "audit user ID" ,"date", "command", "return state"] # we are going to make a csv file (provisionary) and these are the columns/fileds we want for now
        with open('auditDataCSV.csv', 'w') as csvFile:
            csv_writer = csv.writer(csvFile, escapechar='\\')
            csv_writer.writerow(fields)
            csv_writer.writerows(rows)
        
        # and finally we are going to print the csv file
        df = pd.read_csv("auditDataCSV.csv")
        print(df)
        
        
except FileNotFoundError:
    print("that file was not found :(")
# reading works eventhough the file is not txt
