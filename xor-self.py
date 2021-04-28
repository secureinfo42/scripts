#!/usr/bin/env python3
#coding: utf8

import sys
APP="xor-self"

## Manage the error 'BrokenPipeError: [Errno 32] Broken pipe' #####################################

from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

## Functions ######################################################################################

def usage(err):
  print( """
Usage: %s <-u|-x> <-|infile> <-|outfile>

  -    : stdin
  -    : stdout
  -x   : xor
  -u   : unxor

Script will self xorify data. Previous char is key of next xorified char.

Notes  : 

python %s -x private_img.png encrypted.data
cat encrypted.data|python %s -u encrypted.data - > private_img.png

""" % (APP,APP,APP))
  sys.exit(err)

#--------------------------------------------------------------------------------------------------

def self_xor(txt):
  enc = [txt[0]]
  for i in range(1,len(txt)):
    enc.append(txt[i] ^ enc[i-1])
  return(enc)

def self_unxor(enc):
  dec = [enc[0]]
  for i in range(1,len(enc)):
    dec.append(enc[i] ^ enc[i-1])
  return(dec)

## Args ###########################################################################################

if len(sys.argv) != 4:
  usage(1)

buff = ""
if sys.argv[2] == "-":
  buff = sys.stdin.read().encode('utf8')
else:
  filename = sys.argv[2]
  try:
    buff = open(filename,"rb").read()
  except:
    print( "Error: unable to read `%s`" % filename )
    exit()

outfile = "/dev/stdout"
if sys.argv[3] != "-":
  outfile = sys.argv[3]
  try:
    open(outfile,"wb").close()
  except:
    print( "Error: unable to write `%s`" % outfile )
    exit()

if buff:
  if sys.argv[1] == "-u":
    with open(outfile,"wb") as f:
      for c in self_unxor(buff):
        f.write(bytes([c]))

  elif sys.argv[1] == "-x":
    with open(outfile,"wb") as f:
      for c in self_xor(buff):
        f.write(bytes([c])) 
  else:
    usage(1)

exit(0)
