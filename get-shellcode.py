import re
import sys
import os



#
# Globz
#

blue="\033[1;34m"
reset="\033[0m"


#
# Funcz
#

def debug(txt):
	open("/dev/stderr","wt").write(txt)

def get_sections(out):
	sections = []
	for line in out.split("\n"):
		if re.match(r"^0\d+\s\<.+?\>",line):
			addr = line.split(" ")[0]
			name = line.split("<")[1].split(">")[0]
			sections.append({"addr": addr, "name": name, "line": line})
	return(sections)

def show_sections(sections):
	for section in sections:
		print("%-20s \t %s" % (section["addr"], section["name"]))

def get_section(out,section):
	c = out.split(section["line"])[1].split("\n\n")[0]
	return(c)

def get_shellcode(section):
	shellcode = ""
	c = ""
	for line in section.split("\n"):
		if ":" in line:
			shellcode += line.split("\t")[1].replace(" ","")

	for i in range(len(shellcode)-1):
		c += "\\x" + shellcode[i] +  shellcode[i+1]

	return(c)

def objdump(elf):
	cmd = f"objdump -d '{elf}' -M intel,no-aliases,no-notes --visualize-jumps=off"
	ret = os.popen(cmd,"r").read()
	return(ret)



#
# Argz
#

src,sec,c = "","",""

if len(sys.argv) >= 2:
	src=sys.argv[1]

if len(sys.argv) == 3:
	sec=sys.argv[2]

r = objdump(src)
s = get_sections(r)

if len(sys.argv) == 3:
	for i in s:
		if sec == i["name"]:
			c = get_section(r,i)
			break
	debug(f"\n{blue}--- Section:{reset}")
	debug(c)
	h = get_shellcode(c)
	debug(f"\n{blue}--- Shellcode:\n{reset}")
	print(h)

if len(sys.argv) == 2:
	show_sections(s)





