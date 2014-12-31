# ################################################################
# SELinux Integrity Instrumentation
# Mike Libassi 
# 2014/15
# Code source: https://github.com/mikejl/research
# ################################################################

# ################################################################
# Load environmental items
# ################################################################
import md5
import os, sys
import datetime
import subprocess
from pymongo import MongoClient
import timeit
import cProfile, StringIO ,pstats
from tabulate import tabulate
import csv

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
    print "##############################################"
    print " SELinux Integrity Instrumentation (SII) "
    print "##############################################"
    print "Current Test#: ", testnum, "Test System: ", system
    print  "--------------------------------------------------------------------------"
    print "Main Menu"
    print "1. Enter Test #"
    print "2. Enter System Name"
    print "3. Run Collect Scripts"
    print "4. Run Parsing (boolens, service and context)"
    print "5. Run / View Finger Prints"
    print "6. Search /  View Diffs"
    print "7. Search / View Relationships"
    print "8. Tools and Utilities"
    print "9. Exit"
    print "--------------------------------------------------------------------------"
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
# Collect Raw Data from shell scripts 
# ################################################################
def collect(runanswer):
        if runanswer == "Y":
                print "Running collection scripts for system:", system, " Test#:", testnum
                # -------------------------------------
		args = ['sudo', '/home/mike/research/boolean_collect.sh', testnum, 'stdout=None', 'stderr=None']
		str_args = [ str(x) for x in args ]
                bstatus = subprocess.call(str_args)
		if bstatus == 0:
			print "Boolean Collection Done"
		else:
			print "Error in shell script"
		# -------------------------------------
		args = ['sudo', '/home/mike/research/fcontext_collect.sh', testnum]
		str_args = [ str(x) for x in args ]
                cstatus = subprocess.call(str_args)
		if cstatus == 0:
			print "File Context Collection Done"
		else:
			print "Error in shell script"
		# -------------------------------------
		args = ['sudo', '/home/mike/research/service_collect.sh', testnum]
		str_args = [ str(x) for x in args ]
                sstatus = subprocess.call(str_args)
		if sstatus == 0:
			print "Service Collection Done"
		else:
			print "Error in shell script"

                print "Script Colection Done"
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
    #client = MongoClient('localhost', 27017)
    #db = client.booleans
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)    

    # paths
    path = "/home/mike/" + str(testnum) + "/boolean.txt"
    dir_name='/home/mike/'+ str(testnum) + "/"
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
        #Input into mongodb boolean collection 
        #Mongo insert with date/time stamp 
        docinsert = {"Sys": system, "testnum": testnum, "Boolean": Boolean, "Description": Description,"Default": Default,"State": State, "Hash": Hash, "Domain": Domain, "date": datetime.datetime.utcnow()}
        db.booleans.insert(docinsert)


    # Query db collection and mongoexport the collection to csv
    #print list(db.booleans.find())
    print "loaded into booleans: ", db.booleans.count()
    # CSV Output
    print "Export dB results?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d booleans -c booleans --csv -f "Boolean,Description,Default,State,Hash,date" > /home/mike/boolean.csv'], shell=True)
    return

# ################################################################
## File context parse and load
# ################################################################
def fcontextpase():
    #client = MongoClient('localhost', 27017)
    #db = client.fcontext
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)      

    path = "/home/mike/" + str(testnum) + "/fcontext.txt"

    for text in open(path, 'r'):
        fields1 = text.split()
        textlen = len(fields1)
        if textlen == 3:
            fpath = fields1[0]
            ftype = fields1[1]
            ftype2 = fields1[2]
            if "<<None>>" in fields1[2]:
                fcontext = "<<None>>"
                domain = "<<None>>"
            else:
                fcontext = fields1[2]
            if "<<None>>" in fcontext:
                domain = "<<None>>"
            else:
                dfield = fcontext.split(":")
                domain = dfield[2]
        elif textlen == 4:
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

        #TODO - perf
        tohash = fpath+ftype+fcontext
        Hash = md5.new(tohash).hexdigest()
        docinsert = {"Sys": system, "testnum": testnum, "Path": fpath, "Type": ftype, "Domain": domain, "Context": fcontext, "Hash": Hash, "date": datetime.datetime.utcnow()}
        db.fcontext.insert(docinsert)
    
    # Query db collection and mongoexport the collection to csv    
    print "loaded into fcontext: ", db.fcontext.count()
    
    # CSV Output
    print "Export dB results?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d fcontext -c fcontext --csv -f "Path,Type,Context,Hash,date" > /home/mike/fcontext.csv'], shell=True)
    return

# ################################################################
# Service data Parse and Load
# ################################################################
def serviceparse():
    #client = MongoClient('localhost', 27017)
    #db = client.service
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)      

    path = "/home/mike/" + str(testnum) + "/service.running"


    for service in open(path, 'r'):
        field1 = service.split()
        dfile1 = field1[0]
        dfile2 = dfile1.split('.')
        dfile3 = dfile2[0]
        dfile4 = dfile3 + ".info"
        fpath = "/home/mike/" + str(testnum) + "/" + dfile4
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
        #sdomain = "<<none>>"
        service = dfile2[0]
        tohash = service+sdomain+Context
	#TODO = pref
        Hash = md5.new(tohash).hexdigest()
        docinsert = {"Sys": system, "testnum": testnum, "Service": service, "Domain": sdomain, "Context": Context, "Hash": Hash, "date": datetime.datetime.utcnow()}
        db.service.insert(docinsert)
    else:
	print "Done"
        #sdomain = "<<none>>"
    #service = dfile2[0]
    #tohash = service+sdomain+Context
    #Hash = md5.new(tohash).hexdigest()
    #docinsert = {"Sys": system, "testnum": testnum, "Service": service, "Domain": sdomain, "Context": Context, "Hash": Hash, "date": datetime.datetime.utcnow()}
    #print docinsert
    #db.service.insert(docinsert)

    # CSV Output
    print "Export dB results?"
    exportYN=raw_input("Y/N: ")
    if exportYN == "Y":
        print "Exporting..."
        subprocess.call(['mongoexport --host localhost -d service -c service --csv -f "Sys,Service,Domain,Hash,date" > /home/mike/service.csv'], shell=True)
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
    #client = MongoClient('localhost', 27017)
    #db = client.booleans
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)  
    
    global pfp
    hash1 = ""
    hash2 = ""
    
    # perf wrapper start (i)pr where i=function #
    bpr = cProfile.Profile()
    bpr.enable()  #start

    # Finger Print Hash Algorithm
    # sort? db.booleans.find({},{"Hash": 1}).sort(["Boolean"])
    for item in db.booleans.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        pfp = md5.new(tohash).hexdigest()
        hash2 = pfp
        
    bpr.disable() #stop
    boolcount = db.booleans.find().count()
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(bpr, stream=s).sort_stats(sortby).strip_dirs()
    ps.print_stats()
    bfpPerfs = s.getvalue()
    print "***************************************************"
    print "Policy Finger Print: ", pfp
    print "Item Count: ", boolcount
    print "***************************************************"    
    # Store results to dB ########
    # note the xxxPerfs is a type <str>
    bfpPerfs1 = bfpPerfs.lstrip()
    perfline = bfpPerfs1.splitlines()
    smry = perfline[0]
    function_name = sys._getframe().f_code.co_name
    outFileName = system+"-"+function_name+"-"+"test"+testnum+".csv"
    with open(outFileName, "wb") as f:
	writer = csv.writer(f, delimiter=',', quotechar='|')
	for line in perfline:
	    linepart = line.split()
	    writer.writerow(linepart)    
    # raw file
    outProfileName = system+"-"+function_name+"-"+"test"+testnum+".profile"
    ps.dump_stats(outProfileName)
    # Db	    
    db = client.prefdata
    print "Store cProfile results to perfdata dB?"
    YN=raw_input("Y/N: ")
    if YN == "Y":
        docinsert = {"Sys": system, "Testnum": testnum, "Function": function_name, "Perfdata": bfpPerfs, "Perfsmry": smry, "Count": boolcount, "Date": datetime.datetime.utcnow()}
        print "Saving..."
        db.prefdata.insert(docinsert)
    # perf wrapper end #
    
    printfbsub()  
    return
    
# ################################################################
# fContext collection
# ################################################################
def fcontextfp():
    #client = MongoClient('localhost', 27017)
    #db = client.fcontext
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)
    
    global cfp
    hash1 = ""
    hash2 = ""
    
    # perf wrapper start (i)pr where i=function #
    fcpr = cProfile.Profile()
    fcpr.enable()  #start    
    
    # Finger Print Hash Algorithm
    for item in db.fcontext.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        cfp = md5.new(tohash).hexdigest()
        hash2 = cfp
    
    fcpr.disable() #stop
    fcontextcount = db.fcontext.find().count()
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(fcpr, stream=s).sort_stats(sortby).strip_dirs()
    ps.print_stats()
    fcfpPerfs = s.getvalue()
    print "***************************************************"
    print "FContext Finger Print: ", cfp
    print "Item Count: ", fcontextcount
    print "***************************************************"    
    # Store results to dB ########
    # note the xxxPerfs is a type <str>
    # File Output
    fcfpPerfs1 = fcfpPerfs.lstrip()
    perfline = fcfpPerfs1.splitlines()
    smry = perfline[0]
    function_name = sys._getframe().f_code.co_name
    outFileName = system+"-"+function_name+"-"+"test"+testnum+".csv"
    with open(outFileName, "wb") as f:
	writer = csv.writer(f, delimiter=',', quotechar='|')
	for line in perfline:
	    linepart = line.split()
	    writer.writerow(linepart)    
    # raw file
    outProfileName = system+"-"+function_name+"-"+"test"+testnum+".profile"
    ps.dump_stats(outProfileName)       
    # DB Input
    db = client.prefdata
    print "Store cProfile results to perfdata dB?"
    YN=raw_input("Y/N: ")
    if YN == "Y":
	docinsert = {"Sys": system, "Testnum": testnum, "Function": function_name, "Count": fcontextcount, "Perfdata": fcfpPerfs, "Perfsmry": smry, "Date": datetime.datetime.utcnow()}
	print "Saving..."
	db.prefdata.insert(docinsert)
    # perf wrapper end #    

    printfbsub()  
    return
    
# ################################################################
# service collection
# ################################################################
def servicefp():
    #client = MongoClient('localhost', 27017)
    #db = client.service
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)      
    
    global sfp
    hash1 = ""
    hash2 = ""
    
    # perf wrapper start (i)pr where i=function #
    spr = cProfile.Profile()
    spr.enable()  #start    

    # Finger Print Hash Algorithm
    for item in db.service.find({},{"Hash": 1}):
        hash1 = item['Hash']
        tohash = hash1+hash2
        sfp = md5.new(tohash).hexdigest()
        hash2 = sfp
    
    spr.disable() #stop
    servicefpcount = db.service.find().count()
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(spr, stream=s).sort_stats(sortby).strip_dirs()
    ps.print_stats()
    sfpPerfs = s.getvalue()
    print "***************************************************"
    print "Service Finger Print: ", sfp
    print "Item Count: ", servicefpcount
    print "***************************************************"    
    # Store results to dB ########
    # note the xxxPerfs is a type <str>
    sfpPerfs1 = sfpPerfs.lstrip()
    perfline = sfpPerfs1.splitlines()
    smry = perfline[0]
    function_name = sys._getframe().f_code.co_name
    outFileName = system+"-"+function_name+"-"+"test"+testnum+".csv"
    with open(outFileName, "wb") as f:
	writer = csv.writer(f, delimiter=',', quotechar='|')
	for line in perfline:
	    linepart = line.split()
	    writer.writerow(linepart)    
    # raw file
    outProfileName = system+"-"+function_name+"-"+"test"+testnum+".profile"
    ps.dump_stats(outProfileName)
    # Db    
    db = client.prefdata
    print "Store cProfile results to perfdata dB?"
    YN=raw_input("Y/N: ")
    if YN == "Y":
	docinsert = {"Sys": system, "Testnum": testnum, "Function": function_name, "Count": servicefpcount, "Perfdata": sfpPerfs, "Perfsmry": smry, "Date": datetime.datetime.utcnow()}
	print "Saving..."
	db.prefdata.insert(docinsert)
    # perf wrapper end # 
    
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
    if runanswer == "Y":
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
    #client = MongoClient('localhost', 27017)
    client = MongoClient('localhost', 27017)
    str(testnum)
    dbstr = testnum
    DBNAME = dbstr
    db = getattr(client,dbstr)      

    # Service    
    #db = client.service
    serviceres = list(db.service.find({},{"Service":1 ,"Domain":1,"Context":1,"_id":0}))
    distinctsvc = list(db.service.distinct('Domain'))
    # Poicy
    #db = client.booleans
    boolres = list(db.booleans.find({},{"Boolean":1 ,"Domain":1,"State":1, "Default":1, "Description":1,"_id":0}))
    distinctbols = list(db.booleans.distinct('Domain'))
    # File Context
    #db = client.fcontext
    contextres = list(db.fcontext.find({},{"Path":1 ,"Domain":1,"Context":1, "Type":1,"_id":0}))
    distinctfc = list(db.fcontext.distinct('Domain'))
    print "------------------------------------------------------------------------------------"
    print "Current Domains for test: " , testnum
    print "------------------------------------------------------------------------------------"
    print "Services Domains Found:"
    print "_______________________"
    for item in distinctsvc:
        print item
    #print "----------"
    #print "Booleans:"
    #for item in distinctbols:
    #    print item
    #print "----------"
    #print "File Context:"
    #for item in distinctfc:
    #    print item
    print "------------------------------------------------------------------------------------"
    print "Enter domain to search for"
    dsel = raw_input("Domain: ")      
    # Print Results
    #ts = "\t"
    #sep=ts+"       "+ts
    print " "
    print "------------------------------------------------------------------------------------"
    print "Services:"
    print "------------------------------------------------------------------------------------"
    svc_matches = [svc for svc in serviceres if dsel in str(svc['Domain'])]
    print tabulate(svc_matches, headers="keys", tablefmt="pipe")
    #for item in svc_matches:
    #    print "Service:  ", item['Service'],sep, "Domain: ",item['Domain'], sep,"Context:",item['Context']
    print " "
    print "------------------------------------------------------------------------------------"
    print "Booleans:"
    print "------------------------------------------------------------------------------------"
    bol_matches = [bol for bol in boolres if dsel in str(bol['Domain'])]
    print tabulate(bol_matches, headers="keys", tablefmt="pipe")
    #for item in bol_matches:
    #    print "Policy Name:", item['Boolean'],sep,"State:",item['State'],sep,"Default State:",item['Default'],sep,"Desc:",item['Description']
    print " "
    print "------------------------------------------------------------------------------------"
    print "File Contexts:"
    print "------------------------------------------------------------------------------------"
    fc_matches = [fc for fc in contextres if dsel in str(fc['Domain'])]
    print tabulate(fc_matches, headers="keys", tablefmt="pipe")
    #OLD
    #for item in fc_matches:     
    #    print "Domain:",item['Domain'],sep,"Type:",item['Type'],sep,"Context:",item['Context'],sep,"File Path:", item['Path']
    print "------------------------------------------------------------------------------------"
    return

# ################################################################
#  Diff Functions
# ################################################################

def stackdiff():
    client = MongoClient('localhost', 27017)
    
    # perf wrapper start (i)pr where i=function #
    stackpr = cProfile.Profile()
    stackpr.enable()  #start   
    
    #test set 1 data
    str(test1)
    dbstr = test1
    DBNAME = dbstr
    db = getattr(client,dbstr)
    
    # Service    
    t1svcStack = list(db.service.find({},{"Service":1 ,"Sys":1,"Context":1,"Hash":1}).sort("Service"))
    # Poicy
    t1bolStack = list(db.booleans.find({},{"Boolean":1 ,"Domain":1,"State":1, "Default":1,"Hash":1}).sort("Boolean"))
    # File Context
    t1fcStack = list(db.fcontext.find({},{"testnum":1 ,"Sys":1,"Context":1,"Path":1,"Hash":1}).sort("Path"))
    
    # Test set 2 data
    str(test2)
    dbstr = test2
    DBNAME = dbstr
    db = getattr(client,dbstr) 
    # Service    
    t2svcStack = list(db.service.find({},{"Service":1 ,"Sys":1,"Context":1,"Hash":1}).sort("Service"))
    # Poicy
    t2bolStack = list(db.booleans.find({},{"Boolean":1 ,"Domain":1,"State":1, "Default":1,"Hash":1}).sort("Boolean"))
    # File Context
    t2fcStack = list(db.fcontext.find({},{"testnum":1 ,"Sys":1,"Context":1,"Path":1,"Hash":1}).sort("Path"))
    
    #Check for diffs in Service / Policy / File Context
    # Get count for each stack
    t1fclength = len(t1fcStack)
    t2fclength = len(t2fcStack)
    t1svclength = len(t1svcStack)
    t2svclength = len(t2svcStack)
    t1bollength = len(t1bolStack)
    t2bollength = len(t2bolStack)
    
    # Build dict objects for each test(1 AND 2)
    
    # Service
    test1svc_dic = {}
    for line1 in t1svcStack:
	svcname = line1.get("Service")
	svchash = line1.get("Hash")
	test1svc_dic[svcname] = svchash
    
    test2svc_dic = {}
    for line1 in t2svcStack:
	svcname = line1.get("Service")
	svchash = line1.get("Hash")
	test2svc_dic[svcname] = svchash
    
    # Booleans
    test1bol_dic = {}
    for line1 in t1bolStack:
	bolname = line1.get("Boolean")
	bolhash = line1.get("Hash")
	test1bol_dic[bolname] = bolhash
    
    test2bol_dic = {}
    for line1 in t2bolStack:
	bolname = line1.get("Boolean")
	bolhash = line1.get("Hash")
	test2bol_dic[bolname] = bolhash
	
    # fcontext
    test1fc_dic = {}
    for line1 in t1fcStack:
	fcpath = line1.get("Path")
	fchash = line1.get("Hash")
	test1fc_dic[fcpath] = fchash
    
    test2fc_dic = {}
    for line1 in t2fcStack:
	fcpath = line1.get("Path")
	fchash = line1.get("Hash")
	test2fc_dic[fcpath] = fchash    
    
	
    # Service Checks
    print "########## Service Compare Test 1 to Test 2##########"
    svcdiff = test1svc_dic.viewitems()^ test2svc_dic.viewitems()
    print tabulate(svcdiff)
    print "---------------------------------------------------------------------"    
    
    if t1svclength != t1svclength:
	print "Service Count difference"
	print "Set1:",t1svclength," vs ",t2svclength
	for k,v in test1svc_dic.iteritems():
	    if k not in list(test2svc_dic.keys()):
		print "Not in test2 service:"
		print k,v
    else:
	print "Both file context Sets Same Count of:", t1svclength  
    print "---------------------------------------------------------------------"
    
    # Boolean checks
    print "########## Boolean Compare Test 1 to Test 2 ##########"
    boldiff = test1bol_dic.viewitems()^ test2bol_dic.viewitems()
    print tabulate(boldiff)
    print "---------------------------------------------------------------------"    
    
    if t1bollength != t2bollength:
	print "Boolean Service Count difference"
	print "Set1:",t1bollength," vs ",t2bollength
	for k,v in test1bol_dic.iteritems():
	    if k not in list(test2bol_dic.keys()):
		print "Not in test2 booleans:"
		print k,v
    else:
	print "Both Boolean Sets Same Count of:", t1bollength  
    print "---------------------------------------------------------------------"
    
    # File Context checks
    print "########## File Context Compare Test 1 to Test 2 ##########"
    fcdiff = test1fc_dic.viewitems()^ test2fc_dic.viewitems()
    print tabulate(fcdiff)
    print "---------------------------------------------------------------------"    
    
    if t1fclength != t2fclength:
	print "Fcontext Count difference"
	print "Set1:",t1fclength," vs ",t2fclength
	for k,v in test1fc_dic.iteritems():
	    if k not in list(test2fc_dic.keys()):
		print "Not in test2:"
		print k,v
    else:
	print "Both file context Sets Same Count of", t1fclength    
    print "---------------------------------------------------------------------"
    
    stackpr.disable() #stop
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(stackpr, stream=s).sort_stats(sortby).strip_dirs()
    ps.print_stats()
    stackDiffPerfs = s.getvalue()    
    # Store results to dB ########
    # note the xxxPerfs is a type <str>
    stackDiffPerfs1 = stackDiffPerfs.lstrip()
    perfline = stackDiffPerfs1.splitlines()
    smry = perfline[0]
    function_name = sys._getframe().f_code.co_name
    outFileName = system+"-"+function_name+"-"+"test"+testnum+".csv"
    with open(outFileName, "wb") as f:
	writer = csv.writer(f, delimiter=',', quotechar='|')
	for line in perfline:
	    linepart = line.split()
	    writer.writerow(linepart)    
    # raw file
    outProfileName = system+"-"+function_name+"-"+"test"+testnum+".profile"
    ps.dump_stats(outProfileName)
    # Db    
    db = client.prefdata
    print "Store cProfile results to perfdata dB?"
    YN=raw_input("Y/N: ")
    if YN == "Y":
	docinsert = {"Sys": system, "Testnum": testnum, "Function": function_name, "Count": 0, "Perfdata": stackDiffPerfs, "Perfsmry": smry, "Date": datetime.datetime.utcnow()}
	print "Saving..."
	db.prefdata.insert(docinsert)
    # perf wrapper end #   
    
    return



# ################################################################
# FP Diffs.  Test main fingerprints for two tests.
# ################################################################
def diffs():
    global test1
    global test2
    # Get test1 and test 2 from input #
    print "Enter test # for test1"
    test1 = raw_input("Test1:")      
    print "Enter test # for test2"
    test2 = raw_input("Test2:")
    
    print "Runing main diffs for finger prints on test:",test1," vs test:",test2

    
    # Conect to results
    client = MongoClient('localhost', 27017)
    db = client.results

    # perf wrapper start (i)pr where i=function #
    diffpr = cProfile.Profile()
    diffpr.enable()  #start 
    
    # Pull testresults data
    testres = list(db.results.find({},{"testnum":1 ,"contextFP":1,"serviceFP":1,"booleanFP":1, "_id":0}))
    resSet1 = [res for res in testres if test1 in str(res['testnum'])]
    resSet2 = [res for res in testres if test2 in str(res['testnum'])]
    
    # Main diff between both tests
    maindiff = cmp(resSet1, resSet2)
    
    #Extract fingerprints
    t1sfp = resSet1[0].get("serviceFP") 
    t1bfp = resSet1[0].get("booleanFP")  
    t1cfp = resSet1[0].get("contextFP")
    t2sfp = resSet2[0].get("serviceFP")
    t2bfp = resSet2[0].get("booleanFP")
    t2cfp = resSet2[0].get("contextFP")
    
    if maindiff != 0:
	sfpdiff = cmp(t1sfp,t2sfp)
	if sfpdiff != 0:
	    print "************ Seervice FP DIFF!!"
	    print "Run SPF stack diff"
	else:
	    print "NO SPF Diff"
	bfpdiff = cmp(t1bfp,t2bfp)
	if bfpdiff != 0:
	    print "************ Boolean FP DIFF!!"
	    print "Run BPF stack diff"
	else:
	    print "NO BFP Diff"
	cfpdiff = cmp(t1cfp,t2cfp)
	if cfpdiff != 0:
	    print "************ File Context FP DIFF!!"
	    print "Run CFP stack diff?"
	else:
	    print "NO CFP Diff"
    else:
	print "NO DIFFs"
    
    diffpr.disable() #stop
    s = StringIO.StringIO()
    sortby = 'calls'  
    ps = pstats.Stats(diffpr, stream=s).sort_stats(sortby).strip_dirs()
    ps.print_stats()
    DiffPerfs = s.getvalue()    
    
    print "#####################################################"
    print "Finger Prints"
    print "#####################################################"  
    print "Test 1"
    print tabulate(resSet1, headers="keys", tablefmt="pipe")
    print "Test 2"
    print tabulate(resSet2, headers="keys", tablefmt="pipe")
    print ""
    print "#####################################################"
    
    DiffPerfs1 = DiffPerfs.lstrip()
    perfline = DiffPerfs1.splitlines()
    smry = perfline[0]
    function_name = sys._getframe().f_code.co_name
    outFileName = system+"-"+function_name+"-"+"test"+testnum+".csv"
    with open(outFileName, "wb") as f:
	writer = csv.writer(f, delimiter=',', quotechar='|')
	for line in perfline:
	    linepart = line.split()
	    writer.writerow(linepart)    
    # raw file
    outProfileName = system+"-"+function_name+"-"+"test"+testnum+".profile"
    ps.dump_stats(outProfileName)
    # Db    
    db = client.prefdata
    print "Store cProfile results to perfdata dB?"
    YN=raw_input("Y/N: ")
    if YN == "Y":
	docinsert = {"Sys": system, "Testnum": testnum, "Function": function_name, "Count": 0, "Perfdata": DiffPerfs, "Perfsmry": smry, "Date": datetime.datetime.utcnow()}
	print "Saving..."
	db.prefdata.insert(docinsert)

    
    
    print "Run Hash Stack Analysis?"
    runanswer=raw_input("Y or N: ")
    if not runanswer:
	raise ValueError('empty string')
    if runanswer == "Y":
	stackdiff()	        
    return
    

# ################################################################
# Tools - sub menu (put in items like clear db, backup reuslts, etc)
# ################################################################
#TODO
def tools():
    print "Tools menu - TODO"
    print "1. Export Results"
    print "2. Backup full dB"
    print "3. Clear DB!!"
    print "4. Return to Main"
    while True:
        sel=raw_input("Selection: ")
        if sel == "1":
            print "TODO .. export"
            continue
        elif sel == "2":
            print "run mongodump -o <hostname>"
            continue
        elif sel == "3":
            print "TODO .. Clear db"
            continue
        elif sel == "4":
            print "..."
            break     
    return

# ################################################################
# Main menu
# ################################################################
    #1. Enter Test #"
    #2. Enter System name"
    #3. Run Collect Scripts"
    #4. Run parsing (boolens, service and context) sub-menu "
    #5. Run / view finger prints"
    #6. Run / View Diffs"
    #7. Search / View Relationships"
    #8. Tools"
    #9. Exit"
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
            diffs()
            continue       
        elif sel == 7:
            searchrel()
            continue             
        elif sel == 8:
            tools()
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
