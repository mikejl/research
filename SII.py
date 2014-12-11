# ################################################################
# SELinux Integrity Instrumentation
# Mike Libassi 
# 2014/15
# Code source: https://github.com/mikejl/research
#################################################################

# ################################################################
# Load environmental items
# ################################################################
import md5
import os
import datetime
import subprocess
from pymongo import MongoClient
import timeit
import cProfile, pstats, StringIO

# ################################################################
# Set Initial  Vars
# ################################################################
system = "localhost"                       
testnum = 0                                
ip = "local"                               
client = MongoClient('localhost', 27017)   
sfp = 0
cfp = 0
pfp = 0


# ################################################################
# Functions
# ################################################################

# ################################################################
# Main menu Print
# ################################################################
def printmm():
    print "Current Test#: ", testnum, "Test System: ", system
    print  "-------------------------------------------------"
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
# Fingerprint sub menu
# ################################################################
def printfbsub():
    print "Fingerprint menu"
    print "1 = Policy Finger Print"
    print "2 = FContext Finger Print"
    print "3 = Service Finger Print"
    print "4 = Save Results to dB"
    print "5 = Return to Main Menu"
    print "-------------------------"
    return

# ################################################################
# Collect raw data 
# ################################################################
def collect(runanswer):
        if runanswer == "Y":
                print "Running collection scripts"
                #TODO -  look at Popen ( with vars for systemnaem and test #)
                subprocess.call(['sudo /home/mike/research/code/boolean_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/fcontext_collect.sh local'], shell=True)
                subprocess.call(['sudo /home/mike/research/code/service_collect.sh local'], shell=True)
                print "Scripts Ran"
        else:
                print "Test NOT run"
        # check for success?
        return

# ################################################################
# Hash Function - not using .. needs extra tuple joins 
# ################################################################
#def tohash(*hashstring):
#        htuple = [''.join(x) for x in hashstring]
#        htuple2 = ''.join(htuple)
#        return(md5.new(htuple2).hexdigest())

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
        #fields3 = text.split(',', 1)
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
        #TODO - perf
        Hash = md5.new(tohash).hexdigest()
        ## Input into mongodb boolean collection 
        ## Mongo insert with date/time stamp 
        docinsert = {"Sys": system, "testnum": testnum, "Boolean": Boolean, "Description": Description,"Default": Default,"State": State, "Hash": Hash, "Domain": Domain, "date": datetime.datetime.utcnow()}
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
    #TODO - perf
    tohash = fpath+ftype+fcontext
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": testnum, "Path": fpath, "Type": ftype, "Domain": domain, "Context": fcontext, "Hash": Hash, "date": datetime.datetime.utcnow()}
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
    #TODO - perf
    tohash = service+sdomain+Context
    Hash = md5.new(tohash).hexdigest()
    docinsert = {"Sys": system, "testnum": testnum, "Service": service, "Domain": sdomain, "Context": Context, "Hash": Hash, "date": datetime.datetime.utcnow()}
    #print docinsert
    db.service.insert(docinsert)

    ## CSV Output
    subprocess.call(['mongoexport --host localhost -d service -c service --csv -f "Sys,Service,Domain,Hash,date" > /home/mike/research/data/service.csv'], shell=True)
    print "loaded into service: ", db.service.count()
    return

    
# ################################################################
#  Build finderprints of service, policy and context
#
# ################################################################

# ################################################################
# MongoDB booleans collection
# ################################################################
def boolsfp():
    client = MongoClient('localhost', 27017)
    db = client.booleans
    global pfp
    hash1 = ""
    hash2 = ""
    ## perf wrapper start ##
    pr = cProfile.Profile()
    pr.enable()  #start
    
    for item in db.booleans.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        pfp = md5.new(tohash).hexdigest()
        hash2 = pfp
        
    pr.disable() #stop5
    
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    print s.getvalue()
    ## perf wrapper end ##
    
    print "***************************************************"
    print "Policy Finger Print: ", pfp
    print "Item Count: ", db.booleans.find().count()
    print "***************************************************"
    print "Export to CSV?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d boolean -c boolean --csv -f "Hash" > /home/mike/research/p-hlist.txt'], shell=True)
    printfbsub()  
    return
    
# ################################################################
# fContext collection
# ################################################################
def fcontextfp():
    client = MongoClient('localhost', 27017)
    db = client.fcontext
    global cfp
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
    print "Export to CSV?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Hash" > /home/mike/research/fc-hlist.txt'], shell=True)
    printfbsub()  
    return
    
# ################################################################
# service collection
# ################################################################
def servicefp():
    client = MongoClient('localhost', 27017)
    db = client.service
    global sfp
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
    print "Export to CSV?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d service -c service --csv -f "Hash" > /home/mike/research/svc-hlist.txt'], shell=True)
    printfbsub()
    return        
                
# ################################################################
# Save data to results table
# ################################################################
def saveres():
    client = MongoClient('localhost', 27017)
    db = client.results
    print "Enter test results for: ", system, "Test: ", testnum
    print "Current FPs.  ServiceFP:",sfp," PolicyFP:",pfp," ContextFP:",cfp
    dbYN=raw_input("Y/N: ")
    if dbYN == "Y":
        docinsert = {"Sys": system, "testnum": testnum, "serviceFP": sfp, "booleanFP": pfp, "contextFP": cfp, "date": datetime.datetime.utcnow()}
        print "Saving...", docinsert
        db.results.insert(docinsert)
    printfbsub()
    return    

# ################################################################
# Fingerprint submenu
# ################################################################
def fpsub():
    #os.system('clear')
    printfbsub()
    while True:
        is_valid=0
        while not is_valid :
            try :
                sel = int ( raw_input('Enter your choice [1-5] : ') )
                is_valid = 1 ## set it to 1 to validate input and to terminate the while..not loop
            except ValueError, e :
                print ("'%s' is not a valid integer." % e.args[0].split(": ")[1])
        if sel == 1:
            boolsfp()
            continue
        if sel == 2:
            fcontextfp()
            continue
        if sel == 3:
            servicefp()
            continue
        if sel == 4:
            saveres()
        elif sel == 5:
            return()
    return()
    
# ################################################################
# Set Test Number
# ################################################################
def settestnum():
    global testnum
    print "Current test # is: ", testnum
    print "Enter Test Number"
    testnum=raw_input("test: ")
    if not testnum:
        raise ValueError('empty string')
    testnum = testnum
    print "Test Number set at: ", testnum
    return(testnum)

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
    print "Test system name set at: ", system
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
# Pull select fields from db, use python to search / sort data
#TODO - pefr on search

def searchrel():
    client = MongoClient('localhost', 27017)
    print "Enter domain to search for"
    dsel = raw_input("Domain: ")  
    # Service
    db = client.service
    serviceres = list(db.service.find({},{"Service":1 ,"Domain":1,"Context":1,"_id":0})) 
    # Poicy
    db = client.booleans
    boolres = list(db.booleans.find({},{"Boolean":1 ,"Domain":1,"State":1, "Default":1, "Description":1,"_id":0}))  
    # File Context
    db = client.fcontext
    contextres = list(db.fcontext.find({},{"Path":1 ,"Domain":1,"Context":1, "Type":1,"_id":0}))
    #Print
    print "Services:" 
    svc_matches = [svc for svc in serviceres if dsel in str(svc['Domain'])]
    for item in svc_matches:
        print item
    print "---------------------"
    print "Booleans:"
    bol_matches = [bol for bol in boolres if dsel in str(bol['Domain'])]
    for item in bol_matches:
        print item
    print "---------------------"
    print "File Contexts:"
    fc_matches = [fc for fc in contextres if dsel in str(fc['Domain'])]
    for item in fc_matches:
        print item
    print "---------------------"
    return



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
            fpsub()
            continue    
        elif sel == 6:
            print "View Diffs TODO"
            continue       
        elif sel == 7:
            searchrel()
            continue             
        elif sel == 8:
            print "misc sub menu TODO"
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