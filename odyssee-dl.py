from os import system, popen, stat, rename
from sys import argv, stderr
from requests import session

APP = argv[0].split("/")[-1]

###################################################################################################
#
# Aesthetic
#
## 

c_r = "\033[0;31m"
c_g = "\033[0;32m"
c_y = "\033[0;33m"
c_b = "\033[0;34m"
c_m = "\033[0;35m"
c_c = "\033[0;36m" # cyan
c_n = "\033[0m" # none

def vprint(title):
  print(f"[{c_g}+{c_n}] {title}")

def error(errtxt,errcode=0):
  print(f"[{c_r}x{c_n}] Error: {errtxt}\n",file=stderr)
  if errcode:
    exit(errcode)

def get_date():
  d = popen("date").read().strip()
  return(d)



###################################################################################################
#
# HTTP session
#
## 

s = session()

if len(argv) == 2:
  url = argv[1] # 'https://odysee.com/@ERTV:1/Le-Grand-Reset-ou-le-grand-menage-2-great-reset-et-sante:a'
else:
  print(f"Usage: {APP} <url>")
  exit()

## try to reach URL ###############################################################################

try:
  r = s.get(url)
except:
  error("unable to reach URL.",2)

## parse source/dst ###############################################################################

dst = url.split('@')[-1].replace("/","-").replace(":","_") + ".mp4"
tmp = dst+".part"
d = r.text
try:
  udl = r.text.split('"contentUrl"')[1].split('"')[1]
except:
  error("unable to parse URL",3)

try:
  stat(dst)
  error(f"destination '{c_c}{dst}{c_n}' already exists.",1)
  exit()
except FileNotFoundError:
  pass

continue_dl = 0
try:
  stat(tmp)
  vprint(f"Resuming preivous session...")
  continue_dl = 1
  starting_offset = len(open(tmp,"rb").read())
except FileNotFoundError:
  pass

date = get_date()

vprint(f"Started  {c_g}@{date}{c_n}")

vprint(f"Source : '{c_y}{url}{c_n}'")
vprint(f"Stream : '{c_m}{udl}{c_n}'")
vprint(f"Dest.  : '{c_c}{dst}{c_n}'")

vprint(f"Downloading via {c_b}`curl`{c_n} ...")

if continue_dl:
  cmd = f"curl -L -C {starting_offset} -# '{udl}' -o '{dst}.part'"
else:
  cmd = f"curl -L -# '{udl}' -o '{dst}.part'"

try:
  popen(cmd).read()
except KeyboardInterrupt:
  print("")
  error("operation aborted.",130)

rename(tmp,dst)

date = get_date()
vprint(f"Finished {c_g}@{date}{c_n}")

s.close()

