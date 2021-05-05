#!/usr/bin/env python3
#coding: utf-8



###################################################################################################
#
# Libs
#
##

import binascii
from getopt import getopt
from os import popen,system,unlink
from sys import argv, stdin, stdout, exit

import zlib

APP=argv[0].split("/")[-1]



###################################################################################################
#
# Static version : including function basenc()
#
##

def enc_zlib(data,op="-e"):

  try: data = data.encode()
  except: pass

  if op == "-e": return( zlib.compress(data) )
  else: return( zlib.decompress(data) )


###################################################################################################
#
# Usage
#
##

def exemples():
  print(EXEMPLES)
  exit(0)

def usage(err):
  if err:
    if err == 2:
      error("no operation specified\n")
    exit()


  msg ="""
Usage:

  %s <-h|-d|-e> <-f file|->

  -d   : decode
  -e   : encode

Exemples:

  # Encode file '/bin/ls' to output
  %s /bin/ls

  # Encode stdin from /bin/ls
  cat /bin/ls|%s

  # Compute z_lib of stdin (can use `heredoc`)
  %s

  # Encode string
  printf 'myPasswordisverylongandsecret'|%s
"""

  print(msg % (APP,APP,APP,APP,APP) )
  exit(err)

#--------------------------------------------------------------------------------------------------

def file_exists(filename):
  try:
    open(filename,"rb").close()
    return(True)
  except:
    return(False)

#--------------------------------------------------------------------------------------------------

def debug(txt):
  open("/dev/stderr","wt").write("Debug: {}\n".format(txt))

#--------------------------------------------------------------------------------------------------

def my_print(txt):
  print(str(txt)[2:-1]) # b'bZ>NTbZ>NYZwd' -> bZ>NTbZ>NYZwd

#--------------------------------------------------------------------------------------------------

def read_stdin():
  ret = stdin.buffer.read()
  return(ret)

#--------------------------------------------------------------------------------------------------

def error(txt,errcode=0):
  msg = "{}: error: {}".format(APP,txt)
  open("/dev/stderr","wt").write(msg)
  if( errcode ):
    exit(errcode)

#--------------------------------------------------------------------------------------------------

def hexdump(data):
  tmpf = "/tmp/_base_n.tmp"
  open(tmpf,"wb").write(data)
  ret = popen("cat {}|xxd".format(tmpf)).read()
  unlink(tmpf)
  return(ret)

#--------------------------------------------------------------------------------------------------

def read_file(filename):
  ret = ''
  try: ret = open(filename,'rb').read()
  except: error('unable to read file.\n',1)
  return(ret)



###################################################################################################
#
# Argments parsing
#
##

item      = ""
arg_index = 1
op        = "encode"
in_type   = "stdin"
arg_index = 1
data      = None

#--------------------------------------------------------------------------------------------------

base, args, op = "", "", ""

if len(argv[1:]) >= 6: usage(1)

for idx in range(len(argv[1:])+1):
  if argv[idx] == '-e': op = 'encode'
  if argv[idx] == '-d': op = 'decode'
  if argv[idx] == '-h': usage(0)
  if argv[idx] == '-f': data = read_file(argv[idx+1])

if not op:   op='encode'
if not data: data = read_stdin()



###################################################################################################
#
# Operations
#
##

#--- Input data -----------------------------------------------------------------------------------

if op == "encode":
  out = enc_zlib(data,"-e")
  if type(out) is str:
    out = out.encode()
  stdout.buffer.write(out)

if op == "decode":
  try:
    out = enc_zlib(data,"-d")
  except ValueError:
    try:
      out = enc_zlib(data.strip(),"-d")
    except:
      print("Invalid character in input stream.")
      exit(65) # like base64
  if type(out) is str:
    out = out.encode()
  stdout.buffer.write(out)