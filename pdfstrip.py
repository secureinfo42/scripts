#!/usr/bin/env python3
#coding: utf-8
#author: saelyx@cyber-defense.eu


###################################################################################################
#
# Libs
#
##

from getopt import getopt
from os import unlink,rename
from PyPDF2 import PdfFileReader, PdfFileMerger

from sys import argv, stdin, stdout, exit

APP=argv[0].split("/")[-1]

###################################################################################################
#
# Usage
#
##

def usage(err):
  msg ="""
Usage:
  %s <-s|[-f] in_file> [-o out_file] [-r]
  -s : stdin
  -f : input file
  -o : output file

Exemples:
  %s -f report.pdf # by default, create 'report.stripped.pdf'
  %s -f report.pdf -o report-clean.pdf
"""

  print(msg % (APP,APP,APP) )
  exit(err)

#--------------------------------------------------------------------------------------------------

def file_exists(filename):
  try:
    open(filename,"rb").close()
    return(filename)
  except:
    raise "Unable to read input file"
    return(False)

#--------------------------------------------------------------------------------------------------

def error(errtxt,errcode=0):
  msg = "%s: error: "+errtxt
  print(msg % (APP))
  if( errcode ):
    exit(errcode)



###################################################################################################
#
# Argments parsing
#
##

in_type    = "files"
item       = ""
arg_index  = 1

#--------------------------------------------------------------------------------------------------

av = argv[1:]
infile,outfile = "",""
replace = 0
if len(av) == 0:
	usage(0)
for i in range(len(av)):
  if av[i] == "-h":
    usage(0)
  elif av[i] == "-f":
    infile = file_exists(av[i+1])
  elif av[i] == "-o":
    out = av[i+1]
  elif av[i] == "-r":
    replace = 1
if infile == "":
  infile = file_exists(av[0])
if outfile == "":
  outfile = infile[:-4] + '_stripped.pdf'
if not infile:
  error("no input file.",1)






###################################################################################################
#
# Operations
#
##

#--- Merge with data only -------------------------------------------------------------------------

pdf = PdfFileMerger()
try:
  pdf.append(PdfFileReader(infile, 'rb'))
  pdf.write(outfile.format(infile))
except:
  error("unable to strip file",2)

#--- Clean pdf producer (pypdf2) ------------------------------------------------------------------

# Remove :
# << /Producer () >>
# \x3C\x3C\x0A\x2F\x50\x72\x6F\x64\x75\x63\x65\x72\x20\x28\x29\x0A\x3E\x3E
match   = b'\x3c\x3c\x0a\x2f\x50\x72\x6f\x64\x75\x63\x65\x72\x20\x28\x50\x79\x50\x44\x46\x32\x29\x0a\x3e\x3e'
replace = b'\x3c\x3c\x0a\x2f\x50\x72\x6f\x64\x75\x63\x65\x72\x20\x28\x29\x0a\x3e\x3e'
buff = open(outfile,'rb').read()
buff = buff[:1024].replace(match,replace) + buff[1024:]
open(outfile,'wb').write(buff)

if replace == 1:
  unlink(infile)
  rename(outfile,infile)
  outfile = infile

print(outfile)
