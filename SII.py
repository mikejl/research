#
# SELinux Integrity Instrumentation
#
# Prototype Framework 
####################################################################

# Load environmental items
import sys 
import md5
import csv
import os
import pymongo
import json
import datetime
import subprocess
from pymongo import MongoClient
from subprocess import call


# Collect raw data 
def collect(runanswer):
        if runanswer == "Y":
                print "Running collection scripts"
                subprocess.call(['sudo /home/mike/research/code/boolean_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/fcontext_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/service_collect.sh local'], shell=True)
                print "Scripts Ran"
        else:
                print "Test NOT run"
        # check for success?
        return

## MongoDB 
def mongoconnect (dbname):
        client = MongoClient('localhost', 27017)
        db = dbname
        print "Connected to: ", db, "-", client 
        # add a connection test?
        return

# Set System name, test number and the ip 
system = "localhost"    # set per test1 / base 1, etc
test = 1                # set to 1 initally 
ip = "local"            # local only for all tests

print "Enter Test Number"
testnum=raw_input("test: ")
if not testnum:
    raise ValueError('empty string')
test = testnum
print "Test Number set at: ", test

print "Run input scripts"
runanswer=raw_input("Y or N: ")
if not runanswer:
    raise ValueError('empty string')
collect(runanswer)




# Boolean Parse and Load
# Connect to booleans
mongoconnect(client.booleans)

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
        # Send tohas to a hash function return hash valus
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


# File context parse and load


## MongoDB fcontext collection
mongoconnect(client.fcontext)

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


# Service data Parse and Load
mongoconnect(client.service)

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

# ################################################################
## Build finderprints of service, policy and context 
# ################################################################

## MongoDB booleans collection
mongoconnect(client.booleans)

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




## MongoDB fContext collection
mongoconnect(client.fcontext)

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


## MongoDB service collection
mongoconnect(client.service)

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

# Export to CSV    
subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)  

##TODO
# Make a tuple in a system table to have system, date/time, test#, pfp, cfp and sfp 



