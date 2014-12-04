# ################################################################
# SELinux Integrity Instrumentation
# Mike Libassi
# 2014/15
####################################################################

# ################################################################
# Load environmental items
# ################################################################
#import sys 
import md5
#import csv
import os
#import pymongo
#import json
import datetime
import subprocess
from pymongo import MongoClient
#from subprocess import call

# ################################################################
# Set Initial Gloval vars
# ################################################################
system = "localhost"                    # set to localhost initally
test = 0                                # set to 0 initally 
ip = "local"                            # set to local initally
client = MongoClient('localhost', 27017) #Local MongoDB

# ################################################################
# Functions
# ################################################################

# ################################################################
# Main menu Print
# ################################################################
def printmm():
    print "Main Menu"
    print "1. Enter Test #"
    print "2. Enter System Name"
    print "3. Run Collect Scripts"
    print "4. Run Parsing (boolens, service and context)"
    print "5. Run / View Finger Prints"
    print "6. View Diffs"
    print "7. Search / View Relationships"
    print "8. Misc"
    print "9. Exit"
    print "-------------------------"
    return

# ################################################################
# Collect raw data 
# ################################################################
def collect(runanswer):
        if runanswer == "Y":
                print "Running collection scripts"
                # look at Popen ( with vars for systemnaem and test #)
                subprocess.call(['sudo /home/mike/research/code/boolean_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/fcontext_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/service_collect.sh local'], shell=True)
                print "Scripts Ran"
        else:
                print "Test NOT run"
        # check for success?
        return

# ################################################################
# Hash Function
# ################################################################
def tohash(*hashstring):
        htuple = [''.join(x) for x in hashstring]
        htuple2 = ''.join(htuple)
        return(md5.new(htuple2).hexdigest())

# ################################################################
# Boolean Parse and Load
# ################################################################
def booleanparse():
    client = MongoClient('localhost', 27017)
    db = client.booleans

    # path .. may hardcode to local
    path = "/home/mike/research/raw/" + ip + "/boolean.txt"
    # path = "/Users/mike/Documents/raw/" + ip + "/boolean.txt"
    dir_name='/home/mike/research/raw/'+ ip + "/"
    # dir_name='/Users/mike/Documents/raw/'+ ip + "/"
    base_filename='boolean_file'
    filename_suffix = '.domain'

    for text in open(path, 'r'):
        ## Parse the boolean.txt
        fields1 = text.split()
        fields2 = text.split(')', 1)
        fields3 = text.split(',', 1)
        fields4 = text.rsplit('(')
        defaultb = fields4[1].split(',', 1)
        stateb = fields4[1].split(',', 1)
        Boolean = fields1[0].strip()
        Description = fields2[1].strip()
        Default = defaultb[0].strip()
        State = stateb[0].strip()
        base_filename = Boolean
        domain1 = open(os.path.join(dir_name, base_filename + filename_suffix), 'r')
        Domain = domain1.read().strip()
        tohash = Boolean+Default+State+Domain
        # Send tohas to a hash function return hash values
        Hash = md5.new(tohash).hexdigest()
        ## Input into mongodb boolean collection 
        ## Mongo insert with date/time stamp 
        docinsert = {"Sys": system, "testnum": test, "Boolean": Boolean, "Description": Description,"Default": Default,"State": State, "Hash": Hash, "Domain": Domain, "date": datetime.datetime.utcnow()}
        db.booleans.insert(docinsert)


    ## Query db collection and mongoexport the collection to csv
    #print list(db.booleans.find())
    print "loaded into booleans: ", db.booleans.count()
    ## CSV Output
    subprocess.call(['mongoexport --host localhost -d booleans -c booleans --csv -f "Boolean,Description,Default,State,Hash,date" > /home/mike/research/data/boolean.csv'], shell=True)
    return

# ################################################################
## File context parse and load
# ################################################################
def fcontextpase():
    client = MongoClient('localhost', 27017)
    db = client.fcontext

    path = "/home/mike/research/raw/" + ip + "/fcontext.txt"
    #path = "/Users/mike/Documents/raw/" + ip + "/fcontext.txt"

    for text in open(path, 'r'):
        fields1 = text.split()
        fpath = fields1[0]
        ftype = fields1[1]
        ftype2 = fields1[2]
        if not ":" in ftype2:
            ftype = ftype+ftype2
        if "<<None>>" in fields1[2]:
            fcontext = "<<None>>"
            domain = "<<None>>"
        else:
            fcontext = fields1[3]
            if "<<None>>" in fcontext:
                domain = "<<None>>"
            else:
                dfield = fcontext.split(":")
                domain = dfield[2]
    else:
        fcontext = ftype2
        dfield = fcontext.split(":")
        domain = dfield[2]
    # Hash function
    tohash = fpath+ftype+fcontext
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": test, "Path": fpath, "Type": ftype, "Domain": domain, "Context": fcontext, "Hash": Hash, "date": datetime.datetime.utcnow()}
    db.fcontext.insert(docinsert)
    
    ## Query db collection and mongoexport the collection to csv    
    #print list(db.fcontext.find())
    print "loaded into fcontext: ", db.fcontext.count()
    ## CSV Output
    subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Path,Type,Context,Hash,date" > /home/mike/research/data/fcontext.csv'], shell=True)
    return

# ################################################################
# Service data Parse and Load
# ################################################################
def serviceparse():
    client = MongoClient('localhost', 27017)
    db = client.service

    path = "/home/mike/research/raw/" + ip + "/service.running"
    #path = "/Users/mike/Documents/raw/" + ip + "/service.running"

    for service in open(path, 'r'):
        field1 = service.split()
        dfile1 = field1[0]
        dfile2 = dfile1.split('.')
        dfile3 = dfile2[0]
        dfile4 = dfile3 + ".info"
        fpath = "/home/mike/research/raw/" + ip + "/" + dfile4
        #fpath = "/Users/mike/Documents/raw/" + ip + "/" + dfile4
        if os.path.exists(fpath):
            dfile5 = open(fpath,'r')
            dfile6 = dfile5.read().strip()
        if not dfile6:
            sdomain = "<<none>>"
            Context = "<<none>>"
        else:
            context1 = dfile6.split()
            for i in context1:
                context1 = i
                #print i
                break
            con = i.split(":")
            Context = i
            sdomain = con[2]
    else:
        sdomain = "<<none>>"
    service = dfile2[0]
    #Hash function
    tohash = service+sdomain+Context
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": test, "Service": service, "Domain": sdomain, "Context": Context, "Hash": Hash, "date": datetime.datetime.utcnow()}
    #print docinsert
    db.service.insert(docinsert)

    ## CSV Output
    subprocess.call(['mongoexport --host localhost -d service -c service --csv -f "Sys,Service,Domain,Hash,date" > /home/mike/research/data/service.csv'], shell=True)
    print "loaded into service: ", db.service.count()
    return

    
# ################################################################
# # Build finderprints of service, policy and context            #
# ################################################################

# ################################################################
# MongoDB booleans collection
# ################################################################
def boolsfp():
    client = MongoClient('localhost', 27017)
    db = client.booleans

    hash1 = ""
    hash2 = ""

    for item in db.booleans.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        pfp = md5.new(tohash).hexdigest()
        hash2 = pfp

    print "***************************************************"
    print "Policy Finger Print: ", pfp
    print "Item Count: ", db.booleans.find().count()
    print "***************************************************"
    # Export to CSV    
    subprocess.call(['mongoexport --host localhost -d boolean -c boolean --csv -f "Hash" > /home/mike/research/p-hlist.txt'], shell=True)  
    return
    
# ################################################################
# fContext collection
# ################################################################
def fcontextfp():
    client = MongoClient('localhost', 27017)
    db = client.fcontext

    hash1 = ""
    hash2 = ""

    for item in db.fcontext.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        cfp = md5.new(tohash).hexdigest()
        hash2 = cfp
    print "***************************************************"
    print "FContext Finger Print: ", cfp
    print "Item Count: ", db.fcontext.find().count()
    print "***************************************************"

    # Export to CSV    
    subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)  
    return
    
# ################################################################
# service collection
# ################################################################
def servicefp():
    client = MongoClient('localhost', 27017)
    db = client.service

    hash1 = ""
    hash2 = ""

    for item in db.service.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        sfp = md5.new(tohash).hexdigest()
        hash2 = sfp

    print "***************************************************"
    print "Service Finger Print: ", sfp
    print "Item Count: ", db.service.find().count()
    print "***************************************************"

    # Export to CSV ##TODO add results to a system table   
    subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)  
    return        
                
# ################################################################
# TODO
# ################################################################
# Make a tuple in a system table to have system, date/time, test#, pfp, cfp and sfp 

# ################################################################
# Set Test Number
# ################################################################
def settestnum():
    global test
    print "Current test # is: ", test
    print "Enter Test Number"
    testnum=raw_input("test: ")
    if not testnum:
        raise ValueError('empty string')
    test = testnum
    print "Test Number set at: ", test
    return(test)

# ################################################################
# Set systen name
# ################################################################
def setsysname():
    global system
    print "Current System Name: ", system
    print "Enter New System Name or Q to keep"
    name=raw_input("Name: ")
    if name == "Q":
        print "Keeping current name"
        return
    system = name
    print "Test Number set at: ", system
    return(system)


# ################################################################
# Run collect scripts
# ################################################################
def runscripts():
    print "Run input scripts"
    runanswer=raw_input("Y or N: ")
    if not runanswer:
        raise ValueError('empty string')
    collect(runanswer)
    return


# ################################################################
# Run parsing 
# ################################################################
def runsparse():
    print "Select Parse to Run"
    print "1. Service"
    print "2. Boolean"
    print "3. File Context"
    print "4. Back to Main"
    while True:
        sel=raw_input("Selection: ")
        if sel == "1":
            serviceparse()
            continue
        elif sel == "2":
            booleanparse()
            continue
        elif sel == "3":
            fcontextpase()
            continue
        elif sel == "4":
            print "Bye"
            break 
    return


# ################################################################
# Search Relationships
# ################################################################
# example seach with like db.booleans.find({Domain: /ftp/},{})
# example exact search db.booleans.find({Domain: "ftpd_t"},{})
    #client = MongoClient('localhost', 27017)
    #db = client.service
def searchrel():
    client = MongoClient('localhost', 27017)
    print "Enter domain to search on"
    dsel = raw_input("Domain: ")
    #dom = "{'$regex':" + "u" + "'" + dsel + "'" + "}"
    #print dom
    #searchin = '{"Domain": '+dom+'}'+',{"Service":1 ,"Domain":1,"Context":1,"_id":0}'
    #print "Search String: ", searchin
    # Service
    db = client.service
    #serviceres1 = list(db.service.find({'"Domain" :' +dom+'}' +','+'{"Service":1 ,"Domain":1,"Context":1,"_id":0'}))
    serviceres1 = list(db.service.find({"Domain": dsel},{"Service":1 ,"Domain":1,"Context":1,"_id":0}))
    #serviceres1 = list(db.service.find({"Domain": {'$regex': u'ssh'}},{"Service":1 ,"Domain":1,"Context":1,"_id":0}))
    print "Found: ", serviceres1
    #serviceres = list(db.service.find(searchin))
    #db = client.boolean
    #boolres = list(db.boolean.find(searchin))
    #db = client.fcontext
    #contextres = list(db.fcontext.find(searchin))
    #print "Services:"
    #print serviceres
    #print "Booleans:"
    #print boolres
    #print "File Contexts:"
    #print contextres
    return ()



# ################################################################
# Main menu
# ################################################################
    #print "1. Enter Test #"
    #print "2. Enter System name"
    #print "3. Run Collect Scripts"
    #print "4. Run parsing (boolens, service and context) sub-menu "
    #print "5. Run / view finger prints"
    #print "6. View Diffs"
    #print "7. Search / View Relationships"
    #print "8. misc"
    #print "9. Exit"
# ################################################################

def main():
    while True:
        printmm()
        #sel=raw_input("Selection: ")
        is_valid=0
        while not is_valid :
            try :
                sel = int ( raw_input('Enter your choice [1-9] : ') )
                is_valid = 1 ## set it to 1 to validate input and to terminate the while..not loop
            except ValueError, e :
                print ("'%s' is not a valid integer." % e.args[0].split(": ")[1])
        if sel == 1:
            settestnum()
            continue
        elif sel == 2:
            setsysname()
            continue
        elif sel == 3:
            runscripts()
            continue
        elif sel == 4:
            runsparse()
            continue 
        elif sel == 5:
            print "Run FPs"
            continue    
        elif sel == 6:
            print "View Diffs"
            continue       
        elif sel == 7:
            searchrel()
            continue             
        elif sel == 8:
            print "View FPs"
            continue        
        elif sel == 9:
            print "Bye"
            break
        else:
            print "bad entry .. try agin"
            continue

# ################################################################
# MAIN
# ################################################################
if __name__ == "__main__":
    main()

# ################################################################
# END OF CODE
# ################################################################
