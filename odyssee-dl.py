from os import system, popen
from sys import argv
from requests import session

###################################################################################################
#
# Esthetic
#
## 

def vprint(title,info=""):
  g = "\033[1;32m"
  g = "\033[1;32m"
  r = "\033[0m"
  d = ""
  if info:
    d = ":"
  print(f"[{g}+{r}] {title} {d} {info}")

c_g = "\033[0;32m"
c_y = "\033[0;33m"
c_m = "\033[0;35m"
c_r = "\033[0m"



###################################################################################################
#
# HTTP session
#
## 

s = session()

url = argv[1] # 'https://odysee.com/@ERTV:1/Le-Grand-Reset-ou-le-grand-menage-2-great-reset-et-sante:a'

dst = url.split('/')[-1].replace(":","_")

r = s.get(url)

d = r.text

udl = r.text.split('"contentUrl"')[1].split('"')[1]

print("")
vprint("Started {}@{}{}".format(c_g,popen("date").read().strip(),c_r))
vprint("Src : {}'{}'{}".format(c_y,url,c_r))
vprint(" -> : {}'{}'{}".format(c_m,udl,c_r))
vprint("Downloading ...")
cmd = f"wget '{udl}' -O '{dst}'"
system(cmd)
vprint("Finished {}@{}{}".format(c_g,popen("date").read().strip(),c_r))

s.close()

