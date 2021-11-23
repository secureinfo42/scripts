#!/usr/bin/env python3
#coding: utf8

###################################################################################################
#
# Imports
#
##

import os
import re
import sys
import chardet

APP = sys.argv[0].split("/")[-1]
VERBOSE = 0



###################################################################################################
#
# Functions
#
##

## Errors #########################################################################################

def perror(txt,end="\n"):
  """
  Send text to stderr
  """
  global VERBOSE
  if( VERBOSE >= 0 ):
    open("/dev/stderr","w").write(txt+end)

## Validity of extract ############################################################################

def check_validity(count,extract,minlen,maxlen,opt=''):
  """
  Check length and count of extract
  """
  if opt == 'with-padding':
    if count != 1 \
     and len(extract) >= minlen \
     and len(extract) <= maxlen \
     and not extract in extracts:
      return 1
  else:
    if count != 1 \
     and len(extract) >= minlen \
     and len(extract) <= maxlen \
     and extract.count(extract[0]) != len(extract) \
     and not extract in extracts:
      return 1
  return 0

## Read data or portion of data ###################################################################

def read_data(intype,indata="",offset_start=0,offset_end=0):
  try:
    if intype == 'stdin':
      data = open("/dev/stdin","rb").read()
    if intype == 'file':
      data = open(indata,"rb").read()
  except:
    perror("Unable to read file.")
    exit(1)
  if intype == 'string':
    data = str(indata)
  if( offset_end ):
    return(data[offset_start:offset_end])
  else:
    return(data[offset_start:])

## Autodecode encoding ############################################################################  

def byte2str(d):
  return( d.decode(chardet.detect(d)['encoding']) )

## Usage ##########################################################################################

def usage():
  """
  Usage
  """
  global APP
  print("""%s <options> <input>

    input :  -f <infile>
             -s <string>
             -i stdin

    options : -max <maxlen>    : max len for pattern
              -min <minlen>    : min len for pattern
              -start <offset>  : start reading at offset
              -size  <size>    : stop reading at size (offset+size)
              -wp (withpadding search pattern in unique-char string aaaaaaaa)
              -v (show progress)"""
   % APP)


###################################################################################################
#
# Args
#
##

opt_check = data = ""
show_progress = 0
maxlen = 10**6
minlen = 3
intype = 'stdin'
infile = '-'
offset_start = read_size = 0
silently = 0
for idx in range(len(sys.argv[1:])+1):
  try:
    arg = sys.argv[idx]
    if arg == '-h':
      usage()
      exit()
    if arg == '-f':
      intype = 'file'
      infile = sys.argv[idx+1]
    if arg == '-s':
      intype = 'string'
      infile = sys.argv[idx+1]
    if arg == '-i':
      intype = 'stdin'
      infile = sys.argv[idx+1]
    if arg == '-max':
      maxlen = int(sys.argv[idx+1])
    if arg == '-min':
      minlen = int(sys.argv[idx+1])
    if arg == '-skip':
      offset_start = int(sys.argv[idx+1])
    if arg == '-size':
      read_size = int(sys.argv[idx+1])
    if arg == '-wp':
      opt_check = 'with-padding'
    if arg == '-vv':
      show_progress = 1
    if arg == '-v':
      VERBOSE = 1
    if arg == '-q':
      VERBOSE = -1
  except IndexError:
    usage()

data = read_data(intype,infile,offset_start,offset_start+read_size)

if VERBOSE > 0:
  perror("\nConditions:")
  perror(" • Length  : %-4s <= len <= %s" % (minlen,maxlen))
  perror(" • Offsets : %s ->  %s / @%s -> @%s" % (offset_start,offset_start+read_size,hex(offset_start),hex(offset_start+read_size)) )
  perror(" • Size    : %s bytes" % (len(data)))

m = 0
for j in range( 1,int(len(data)/1.5) ):
  for i in range( 0,len(data),j ):
    m += 1

c = 0
extracts = {}
for j in range( 1,int(len(data)/1.5) ):
  for i in range( 0,len(data),j ):
    try:
      p = int(c/m*100)
      if show_progress:
        perror("\rLoading %s%%..." % (p),end="")
      c += 1
      extract = data[i:i+j]
      count = data.count( extract )
      if check_validity(count,extract,minlen,maxlen,opt_check):
        extracts.update( {extract:count} )
    except KeyboardInterrupt:
      perror("\rUser aborted operation.")
      exit(130)

if VERBOSE == -1:
  for extract in extracts:
    print("%s" % (byte2str(extract)) )
else:
  print("")
  perror("%-6s | %-6s | %s" % ('Count', 'Length', 'Pattern') )
  perror("%-6s | %-6s | %s" % ('-'*6, '-'*6, '-'*20 ) )
  for extract in extracts:
    print("%-6s | %-6s | %s" % (extracts[extract], len(extract), byte2str(extract) ) )
  print("")


