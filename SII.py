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



# System Info
# CentOS7 and Fedora20 


# Need user (or use root) to be able to run root commands (part of root group)? 
# Use user and root in authorized_keys
# Setup SSH key auth (id_res.pub from research1 to each sever)
# scp .ssh/id_rsa.pub mike@192.168.1.93:.ssh/authorized_keys
# 
# Code will run on local host.  SSH keys will be used for data collection.


# Data Collection 
# ** A system sertup script (setup SSH keys and collect data)?
# ** Data from the system table on systemd (Y or N) could be used to determin service collection.
# System name = Sys
# IP Address = IP
# systemd = Y|N
# 
# ** Pass IP address and SystemD Y|N?
# 
# systemd service collection (root call):
# systemctl --type=service --no-legend
# Columes UNIT  LOAD  ACTIVE SUB  DESCRIPTION
# 1. Pull Unit, Descripition
# 2. Add date/time and Sys
# 3. Pull in Context
# postprocessing pull list of column 1 
# cat service.list | awk {'print $1'} > service.names
# also
# cat service.list  | grep "running" | awk {'print $1'} > service.running
# 
# For each service in the service.running list
# ps -efZ | grep <service> 
# 1. Get context
# 2. PID?
# 3. Parse domain
# 
# Load into Service: Sys, Date Time, Name, Desc, Context, Domain
# 
# Shell Scripts to collect raw data on localhost (local)

# sudo scripts for collection of raw data
subprocess.call(['sudo /home/mike/research/code/boolean_collect.sh local'], shell=True)


subprocess.call(['sudo /home/mike/research/code/fcontext_collect.sh local'], shell=True)


subprocess.call(['sudo /home/mike/research/code/service_collect.sh local'], shell=True)



# Set System name, test number and the ip (set to local for now)
system = "centOS1"
test = 1
ip = "local"


# Boolean Parse and Load


## MongoDB booleans collection
client = MongoClient('localhost', 27017)
db = client.booleans

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
        Hash = md5.new(tohash).hexdigest()
        #system = "centOS1"
        ## Input into mongodb boolean collection 
        ## Mongo insert with date/time stamp 
        docinsert = {"Sys": system, "testnum": test, "Boolean": Boolean, "Description": Description,"Default": Default,"State": State, "Hash": Hash, "Domain": Domain, "date": datetime.datetime.utcnow()}
        db.booleans.insert(docinsert)


## Query db collection and mongoexport the collection to csv
#print list(db.booleans.find())
print "loaded into booleans: ", db.booleans.count()
## CSV Output
#subprocess.call(['mongoexport --host localhost -d booleans -c booleans --csv -f "Boolean,Description,Default,State,Hash,date" > /home/mike/research/data/boolean.csv'], shell=True)


# File context parse and load


## MongoDB fcontext collection
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
    tohash = fpath+ftype+fcontext
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": test, "Path": fpath, "Type": ftype, "Domain": domain, "Context": fcontext, "Hash": Hash, "date": datetime.datetime.utcnow()}
    db.fcontext.insert(docinsert)
    
## Query db collection and mongoexport the collection to csv
#print list(db.fcontext.find())
print "loaded into fcontext: ", db.fcontext.count()
## CSV Output
#subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Path,Type,Context,Hash,date" > /home/mike/research/data/fcontext.csv'], shell=True)


# <headingcell level=2>

# Service data Parse and Load

# <codecell>

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
    tohash = service+sdomain+Context
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": test, "Service": service, "Domain": sdomain, "Context": Context, "Hash": Hash, "date": datetime.datetime.utcnow()}
    #print docinsert
    db.service.insert(docinsert)

## CSV Output
#subprocess.call(['mongoexport --host localhost -d service -c service --csv -f "Sys,Service,Domain,Hash,date" > /home/mike/research/data/service.csv'], shell=True)
print "loaded into service: ", db.service.count()

# ################################################################

## Build finderprints of service, policy and context 

# ################################################################

## MongoDB booleans collection
client = MongoClient('localhost', 27017)
db = client.booleans

hash1 = ""
hash2 = ""

# Retuured from Mongo {u'_id': ObjectId('53af3ccad6155e0284f64b1a'), u'Hash': u'a7cdceecdcf39d7ab89e5604c121b719'}

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
#subprocess.call(['mongoexport --host localhost -d boolean -c boolean --csv -f "Hash" > /home/mike/research/p-hlist.txt'], shell=True)  



## MongoDB fContext collection
client = MongoClient('localhost', 27017)
db = client.fcontext

hash1 = ""
hash2 = ""

# Retuured from Mongo {u'_id': ObjectId('53af3ccad6155e0284f64b1a'), u'Hash': u'a7cdceecdcf39d7ab89e5604c121b719'}

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
#subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)  



## MongoDB service collection
client = MongoClient('localhost', 27017)
db = client.service

hash1 = ""
hash2 = ""

# Retuured from Mongo {u'_id': ObjectId('53af3ccad6155e0284f64b1a'), u'Hash': u'a7cdceecdcf39d7ab89e5604c121b719'}

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
#subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)  




