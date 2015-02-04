research
========
SELinux Integrity Instrumentation (SII)
Dissertation code and files.
To be pulled into test systems:

SII.py - The main SII testing framework ran on lab systems (capturing and saving cProfile data)
SIIv2.py - Copy with Profile data output off and changed to allow running on local system against dB backups.

Required:  
Python 2.7  
MongoDB  
pymongo  
setools  
 

Python packages used:  
import md5  
import csv  
import os, sys  
import datetime  
import subprocess  
from pymongo import MongoClient  
import timeit  
import cProfile, StringIO ,pstats  
from tabulate import tabulate  
