#!/opt/local/bin/python3.8
#coding: utf8

#######################################################################################################################
#
# Libs
#
##

import sys
import re
import requests
import ssl
import OpenSSL
import json
import socket
import pygeoip
from bs4       import BeautifulSoup
from os        import popen, system, unlink, stat
from scapy.all import IP,ICMP,sr1,conf
from hashlib   import sha1,md5,sha256
requests.packages.urllib3.disable_warnings() 
conf.verb = 0



#######################################################################################################################
#
# Globalz
#
##

APP = "ip-info"

# HTTP headers ########################################################################################################

COMMON_HEADERS = {
  'User-Agent'      : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:83.0) Gecko/20100101 Firefox/83.0',
  'Accept'          : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'Accept-Language' : 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
  'Accept-Encoding' : 'gzip, deflate',
  'Connection'      : 'keep-alive',
  'Pragma'          : 'no-cache',
  'Cache-Control'   : 'no-cache',
  'Upgrade-Insecure-Requests': '1',
}

# DIG #################################################################################################################

DNS_SERVER = "9.9.9.9"

# Checkup #############################################################################################################

PATHS          = ("/bin","/usr/bin","/usr/local/bin","/opt/local/bin","/opt/local/Library/Frameworks/Python.framework/Versions/3.8/bin/","/opt/iunix/Resources/bin/")
EXES           = ("dig", "nmap", "whois", "ip2cc", "shodan","tput","grep","wafw00f")
GEOIP_DB       = pygeoip.GeoIP("/usr/local/share/GeoIP/GeoIP.dat")
SEPARATOR      = "\033[1;32m / \033[0m"
DEBUG          = 1
TERM_WIDTH     = int(popen("tput cols 2>/dev/null||echo 120").read().strip())
SHODAN         = "/opt/local/Library/Frameworks/Python.framework/Versions/3.8/bin/shodan"
WAFW00F        = "/opt/local/Library/Frameworks/Python.framework/Versions/3.8/bin/wafw00f"
# SECURITYTRAILS = "/opt/iunix/Resources/bin/curl.securitytrails"
NMAP_PORTS     = "20-1024,80,1080,8080,10080,81,1081,8081,10081,82,1082,8082,10082,443,8443,10443,20443,30443,49152"
NMAP_CMD       = "nmap --host-timeout 3 --max-retries 3 --max-scan-delay 3 -Pn -p {} -T4 %s 2>/dev/null".format(NMAP_PORTS)
EASY_LIST      = "https://easylist.to/easylist/easylist.txt"

#######################################################################################################################
#
# Funcz
#
##

# Errors ##############################################################################################################

def usage(errcode=0):

  print("Usage : %s [-j|-p|-t] <URL|IP> [what]".format(APP))
  print("        %s <-I report.json> [what]".format(APP))
  print("")
  print("  what : target, icmp, dns, shodan, http, tls, whois, ioc, scan") # securitytrails
  print("")
  print("  -j : output in JSON format")
  print("  -p : output in Python variable format")
  print("  -t : output as text")
  print("  -n : output without colors")
  print("  -I : import JSON result")
  print("")
  exit(errcode)

def check_connect(ip,port):
  c = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  c.settimeout(3)
  try:
    c.connect( ( ip , int(port) ) )
    return 0
  except:
    perror("unable to connect to `{}:{}`".format(ip,port))
    return 1

def check_tools():
  tools_found = {}
  for exe in EXES:
    for path in PATHS:
      tool = path+'/'+exe
      try:
        open(tool,"rb").close()
        tools_found.update({exe: tool})
      except FileNotFoundError:
        continue
    if exe not in tools_found:
      perror("program `{}` is missing\n".format(exe),2)

def perror(errtxt,errcode=0):
  global DEBUG
  msg = "Error: {}\n".format(errtxt)
  if DEBUG:
    try:
      open("/dev/stderr","wt").write(msg)
    except:
      print("{}".format(msg))
  if errcode>0:
    sys.exit(errcode)

# ICMP infos ##########################################################################################################

def icmp_infos(ip):
  pkt = IP(dst=ip)/ICMP(type=8,code=0)
  ans = sr1(pkt,timeout=2)
  ttl = '-'
  os  = 'Unknown'
  distance = '?'
  if ans:
    ttl = ans.ttl
    if ans.ttl > 64 and ans.ttl <= 128:
      distance = 128-ans.ttl
      os = 'Windows'
    elif ans.ttl <= 64:
      distance = 64-ans.ttl
      os = 'Linux'
    elif ans.ttl > 128:
      distance = 255-ans.ttl
      os = 'Gateway?'
  return(ttl,os,str(distance))

# IP formats ##########################################################################################################

def ip2long(ip):
  ip    = [int(x) for x in ip.split(".")]
  long  = (ip[0] << 24)
  long += (ip[1] << 16)
  long += (ip[2] << 8)
  long += ip[3]
  return(long)

def long2ip(long):
  long = int(long)
  ip = [0,0,0,0]
  ip[0] = (long & 0xFF000000) >> 24
  ip[1] = (long & 0x00FF0000) >> 16
  ip[2] = (long & 0x0000FF00) >> 8
  ip[3] = (long & 0x000000FF)
  ip = [str(x) for x in ip]
  ip = '.'.join(ip)
  return(ip)

def long2ip_rev(long):
  long = int(long)
  ip = [0,0,0,0]
  ip[3] = (long & 0xFF000000) >> 24
  ip[2] = (long & 0x00FF0000) >> 16
  ip[1] = (long & 0x0000FF00) >> 8
  ip[0] = (long & 0x000000FF)
  ip = [str(x) for x in ip]
  ip = '.'.join(ip)
  return(ip)

def ip2long_rev(ip):
  ip    = [int(x) for x in ip.split(".")]
  long  = (ip[3] << 24)
  long += (ip[2] << 16)
  long += (ip[1] << 8)
  long += ip[0]
  return(long)

def ip2hex(ip):
  ip = ["0"*(4-len(hex(int(x))))+hex(int(x)) for x in ip.split(".")]
  hx = ''.join(ip)
  hx = "0x"+hx.replace("0x","")
  return(hx)

# WAF detection #######################################################################################################

def do_wafw00f(url):
  global WAFW00F
  infos = []
  cmd = "%s --output=- %s 2>/dev/null" % (WAFW00F,url)
  res = popen(cmd).read().strip()
  ret = []
  try:
    ret = res.split(url)[1]
    ret = re.sub(r'^\s+','',ret)
    ret = re.sub(r'\s+',' ',ret)
  except:
    pass
  return(ret)

# Open ports ##########################################################################################################

def do_nmap(ip):
  global NMAP_CMD
  infos = []
  cmd = NMAP_CMD % ip
  cmd = cmd + "|grep '/tcp'|grep -w open|cut -d'/' -f1"
  res = [ x.strip() for x in popen(cmd).readlines() ]
  infos = ','.join(res)
  # for ret in res:
  #   infos.append(ret)
  return(infos)

# DNS informations ####################################################################################################

def do_adcheck(host):
  infos = []
  s = requests.session()
  r = s.get(EASY_LIST)
  if host in r.text:
    return([{"easy_list": "found" }])
  return([])

# DNS informations ####################################################################################################

def do_dig(host):
  global DNS_SERVER, SEPARATOR
  infos = []
  cmd = "dig @%s %s 2>&1|grep -v '^;'|grep .|col|sed -r 's/\\s+/ /g'" % (DNS_SERVER,host)
  res = [ x.strip() for x in popen(cmd).readlines() ]
  for ret in res:
    infos.append(ret) # .replace("\t"," "))
  # infos = SEPARATOR.join(infos)
  return(infos)

# DNS inverse resolution ##############################################################################################

def host_rev(ip):
  """
  Inverse DNS resolution
  """
  global SEPARATOR
  try:
    reverse_name = socket.gethostbyaddr(ip)
  except socket.herror:
    perror("unable to do a reverse resolution to `%s`" % ip)
    return(ip)

  infos = []
  for i in reverse_name:
    if type(i) is list:
      for j in i:
        infos.append(j)
    else:
      infos.append(i)
  # infos = SEPARATOR.join(infos)
  return(infos)

# GeoIP ###############################################################################################################

def geoip(ip):
  global GEOIP_DB
  country = GEOIP_DB.country_code_by_addr(ip)
  if not country:
    country = "Unknown"
  return(country)

# Hash ################################################################################################################

def md5sum(data):

  return( md5(data.encode()).hexdigest() )

def sha1sum(data):

  return( sha1(data.encode()).hexdigest() )

def sha256sum(data):

  return( sha256(data.encode()).hexdigest() )

# HTTP ################################################################################################################

def wget(url):
  global COMMON_HEADERS
  redirs = []
  s = requests.session()
  try:
    r = s.get(url,headers=COMMON_HEADERS,verify=False)
  except requests.exceptions.ConnectionError:
    try:
      r = s.get(url,headers=COMMON_HEADERS,verify=False,allow_redirects=False)
    except:
      perror("unable to connect to '{}'".format(url),-3)
      return("-","-","-")
  htmldata = r.text
  htmlstruct = BeautifulSoup(htmldata,features="lxml")
  for redir in r.history:
    redirs.append(redir.url)
  title = ''
  try:
    title = htmlstruct('title')[0]
  except IndexError:
    pass
  # redirs = SEPARATOR.join(redirs)
  return(title,redirs,r)

def get_doms(htmldata=""):
  global APP, SEPARATOR
  found = ""
  url_regex = r"(\w+://[0-9a-zA-Z\/\-\.\\\?\&\#\(\)\[\]\{\}_%:=,;]{1,}/)"
  rgx = re.compile(url_regex)
  found = set([ x.split("/")[2] for x in re.findall(url_regex,htmldata) ])
  found = [ x for x in found ]
  # found = SEPARATOR.join(found)
  return(found)

# TLS #################################################################################################################

def parse_x509date(x509_date):
  x509_date = x509_date.decode()
  year    = x509_date[0:4]
  month   = x509_date[4:6]
  day     = x509_date[6:8]
  hour    = x509_date[8:10]
  minutes = x509_date[10:12]
  return( year +"/"+month+"/"+day+"@"+hour+":"+minutes )

def _get_alts(host,port):
  global SEPARATOR
  cmd  = 'openssl s_client -showcerts -connect %s:%s 2>/dev/null </dev/null' % (host,port)
  cmd += '| openssl x509 -noout -text 2>/dev/null'
  cmd += '| grep -oP "(?<=DNS:)[^,]+"'
  altnames = [ x.strip() for x in popen(cmd).readlines() ]
  # altnames = SEPARATOR.join(altnames)
  return( altnames )

def cert_infos(host,port):
  infos      = {}
  expiration,notBefore,notAfter,subject,altnames = "-","-","-","-","-"
  try:
    cert       = ssl.get_server_certificate((host,port))
    x509       = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    subject    = x509.get_subject()
    subject    = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
    expiration = x509.has_expired()
    notAfter   = parse_x509date(x509.get_notAfter())
    notBefore  = parse_x509date(x509.get_notBefore())
    altnames   = _get_alts(host,port)
  except:
    perror("problem while gathering certificate informations")
  return( expiration,notBefore,notAfter,subject,altnames )

# Securitytrails ######################################################################################################

def do_securitytrails(host):
  securitytrails_result = []
  return(securitytrails_result)
  # json_text = popen("{} history/{}/dns/a 2>/dev/null".format(SECURITYTRAILS,host)).read().strip()
  # json_data = json.loads(json_text)
  # if 'records' in json_data:
  #   for result in json_data['records']:
  #     if len(result['values']) >= 1:
  #       securitytrails_result.append( {
  #         'ip': result['values'][0]['ip'] ,
  #         'first_seen': result['first_seen'] ,
  #         'last_seen': result['last_seen'] ,
  #       } )

  # return(securitytrails_result)

# Shodan ##############################################################################################################

def do_shodan(ip):
  global SHODAN
  global OUTFORMAT
  # filter_shodan = re.sub(r'(^ww\w+\.)','',host)
  # keyword = 'hostname'
  # if re.match(r'^\d+\.\d+\.\d+\.\d+',filter_shodan):
  filter_shodan = ip
  keyword = 'ip'
  filter_shodan = keyword+':'+filter_shodan
  items = []
  cmd  = "{} search --separator ';' ".format(SHODAN)
  cmd += "--fields "
  cmd += "ip,port,hostnames,city,org,ssl.cert.issuer.CN,ssl.cert.issuer.C,ssl.cert.issuer.L,http.server,http.title "
  cmd += "{}  2>/dev/null|grep .".format(filter_shodan)
  results = [ x.rstrip() for x in popen(cmd).readlines() ]
  for line in results:
    line         = line.strip()
    ip           = line.split(';')[0]
    ip           = long2ip(ip)
    port         = line.split(';')[1]
    rev          = line.split(';')[2]
    city         = line.split(';')[3]
    org          = line.split(';')[4]
    issuer       = line.split(';')[5]
    cert_country = line.split(';')[6]
    cert_city    = line.split(';')[7]
    http_server  = line.split(';')[8]
    http_title   = line.split(';')[9]
    # items.append( "%-15s: %-5s | %s (%s)" % (ip,port,rev,org) )
    item = {'ip':ip, 'port':port, 'rev':rev, 'org':org, 'http-srv': http_server, 'http-title': http_title}
    if item not in items:
      items.append( item )
  return(items,filter_shodan)


# Robots ##############################################################################################################

def get_robot(url):
  disallowed , sitemaps = [] , []
  # disallowed = sitemaps = [] # Same pointer!
  global COMMON_HEADERS
  s = requests.session()
  try:
    r = s.get(url+"robots.txt",headers=COMMON_HEADERS,verify=False,allow_redirects=False)
  except:
    return(disallowed,sitemaps)

  html_text = r.text.replace("\r","\n").split("\n")
  for entry in html_text:
    entry = entry.strip()
    if 'disallow:' in entry.lower():
      disallowed.append(entry)
    if 'sitemap:' in entry.lower():
      sitemaps.append(entry)
    else:
      continue
  disallowed = list(set(disallowed))
  sitemaps   = list(set(sitemaps))

  return(disallowed,sitemaps)

# Whois ###############################################################################################################

def do_whois(ip):
  """
  Return object with whois information
  """
  global SEPARATOR
  infos = {}
  index = 0
  whois = popen('whois {}'.format(ip),'r').readlines()
  for line in whois:
    line = line.strip()
    if len(line) == 0:
      index += 1
    if re.match(r'^%',line) or re.match(r'^#',line) or re.match(r'^remarks',line) or re.match(r'^Comment',line) or 'descr' in line or not line:
      continue
    # if re.match(r'^OrgTech',line) or re.match(r'^OrgNOC',line):
    #   continue
    whois_keyword = line.split(':')[0].strip()
    whois_data    = ' '.join(line.split(':')[1:]).strip()

    str_index = 'whois-%s-%s' % (whois_keyword,str(index))

    if( len(whois_data.strip()) ) > 1:
      infos.update( {str_index: "'"+whois_data+"'"} )

    # if index<10:
    #   str_index = "0"+str(index)
    # key   = "Whois"+"["+str_index+"]-"+line.split(":")[0]
    # key , value = "" , ""
    # try:
    #   key , value = line.split(":")[0].strip() , line.split(":")[1].strip()
    # except:
    #   continue
    # if key in infos:
    #   if "OrgTechPhone" in key or "OrgTechName" in key or "OrgTechMail" in key:
    #     infos[key].append(value)
    #   else:
    #     if value not in infos[key]:
    #       infos[key].append(value)
    # else:
    #   infos.update( {key: [value]} )

  # for info in infos:
  #   infos[info] = SEPARATOR.join(infos[info])
  return(infos)

# Parsing #############################################################################################################

def parse_url(url):
  rgx = r"^(\w+)://([a-zA-Z0-9-_\.]+):?(\d*)/?"
  if not 'http' in url and not '://' in url:
    url = 'https://{}/'.format(url)
  rgx = re.compile(rgx)
  ret = re.findall(rgx,url)
  try:
    proto = ret[0][0]
    host  = ret[0][1]
    port  = ret[0][2]
  except IndexError:
    perror("unable to parse URL : `{}`".format(url),1)
  if not port:
    if proto == 'https': port = 443
    if proto == 'http':  port = 80
    if proto == 'ftp':   port = 21
    if proto == 'ftps':  port = 990
    if proto == 'rtsp':  port = 554
  if ret:
    try:
      ip = socket.gethostbyname(host)
    except socket.error:
      perror("unable to resolve host `{}`\n".format(host))
      sys.exit()
  return(url,proto,host,port,ip)

# Reading infos from JSON #############################################################################################

def import_json(filepath): 
  buff , ret = "" , ""
  try:
    buff = open(filepath).read().strip()
  except:
    perror("unable to read input file",3)
  try:
    json_data = json.loads(buff)
  except:
    perror("unable to read data",4)
  return(json_data)

# Gathering infos #####################################################################################################

def srvinfo(url):
  #--------------------------------------------------------------------------------------------------------------------
  infos = {}
  #--------------------------------------------------------------------------------------------------------------------
  url, protocol, host, port, ip = parse_url(url)
  check_connect(ip,port)
  infos["TARGET"]  = {
    'URL'          : url,
    'Protocol'     : protocol,
    'Host'         : host,
    'Port'         : port,
    'IP'           : ip,
    'Country'      : geoip(ip)
  }
  #--------------------------------------------------------------------------------------------------------------------
  ttl,os,distance  = icmp_infos(ip)
  infos["ICMP"]    = {
    'TTL'          : ttl,
    'Supposed-OS'  : os,
    'Distance'     : distance,
  }
  #--------------------------------------------------------------------------------------------------------------------
  open_ports = do_nmap(ip)
  waf        = do_wafw00f(url)
  infos["SCAN"]    = {
    'Waf'          : waf,
    'Openports'    : open_ports,
  }
  #--------------------------------------------------------------------------------------------------------------------
  dig,rev = do_dig(host),host_rev(ip)
  infos["DNS"]     = {
    'Dig'          : dig,
    'Reverse-DNS'  : rev,
  }
  #--------------------------------------------------------------------------------------------------------------------
  results_ad = do_adcheck(host)
  infos["ADS"]  = {
    'Easy-List'    : results_ad,
  }
  #--------------------------------------------------------------------------------------------------------------------
  results_shodan, filter_shodan = do_shodan(ip)
  infos["SHODAN"]  = {
    'Filter'       : filter_shodan,
    'Results'      : results_shodan,
  }
  #--------------------------------------------------------------------------------------------------------------------
  # results_securitytrails = do_securitytrails(host)
  # infos["SECURITYTRAILS"]  = {
  #   'DNS-History'   : results_securitytrails,
  # }
  #--------------------------------------------------------------------------------------------------------------------
  title,redirections,htmlobject = wget(url)
  disallowed,sitemaps = get_robot(url)
  if type(htmlobject) is requests.models.Response:
    infos["HTTP"]        = {
      'Title'            : str(title),
      'Status-Code'      : htmlobject.status_code,
      'Error-Reason'     : htmlobject.reason,
      'Redirections'     : redirections,
      'External-Dom'     : get_doms(htmlobject.text),
      'Robots-Sitemaps'  : sitemaps,
      'Robots-Disallowed': disallowed,
    }
    for header in htmlobject.headers:
      infos["HTTP"].update( {header: htmlobject.headers[header]} )

  #--------------------------------------------------------------------------------------------------------------------
  if protocol == 'https':
    expiration,notBefore,notAfter,subject,altnames = cert_infos(host,port)
    infos["TLS"]     = {
      'Expiration'   : expiration,
      'notBefore'    : notBefore,
      'notAfter'     : notAfter,
      'subject'      : subject,
      'altnames'     : altnames,
    }
  #--------------------------------------------------------------------------------------------------------------------
  infos["WHOIS"]   = do_whois(ip)
  #--------------------------------------------------------------------------------------------------------------------
  infos["IOC"]     = {
    'hex(IP)'      : ip2hex(ip),
    'long(IP)'     : ip2long(ip),
    'long_rev(IP)' : ip2long_rev(ip),
    'sha1(IP)'     : sha1sum(ip),
    'sha1(host)'   : sha1sum(host),
  }

  htmltext = ""
  try:
    htmltext = htmlobject.text
  except:
    pass

  if htmltext: # type(htmlobject) is not requests.models.Response:
    infos["IOC"].update({
      'md5(html)'    : md5sum(htmltext),
      'sha256(html)' : sha256sum(htmltext),
      'size(html)'   : len(htmltext),
    })
  #--------------------------------------------------------------------------------------------------------------------
  return(infos)

# Display infos #######################################################################################################

def browse_object(my_object,color_opt,section):
  global TERM_WIDTH
  CURRENT_TERM_WIDTH = TERM_WIDTH - 2
  c_green   = "\033[0;32m"
  c_yellow  = "\033[1;33m"
  c_blue    = "\033[1;34m"
  c_lgreen  = "\033[1;32m"
  c_magenta = "\033[0;35m"
  c_grey    = "\033[0;30m"
  c_reset   = "\033[0m"
  if color_opt == 'n':
    c_green = c_yellow = c_blue = c_lgreen = c_reset = ""

  padding = "="*(CURRENT_TERM_WIDTH-len(section)-5)
  print("%s\n=== %s %s%s\n" % (c_lgreen,section,padding,c_reset))
  for field in my_object[section]:
    value = my_object[section][field]
    if type(value) is list:
      if len(value) > 1:
        print("%s%-35s : %s" % (c_green,field,c_reset))
        for item in value:
          if type(item) is dict:
            out = ""
            for field in item:
              out += "%s%s%s: %s, " % (c_magenta,field,c_reset,item[field])
            print("%s%-35s - %s %s" % (c_yellow," ",c_reset,out))
          else:
            print("%s%-35s - %s %s" % (c_yellow," ",c_reset,item))
        print(c_grey+"-"*CURRENT_TERM_WIDTH+"\033[0m")
      else:
        # if section == "SHODAN":
        #   print(value)
        #   print(type(value))
        if type(value) is str:
          print("%s%-35s = %s %s" % (c_green,field,c_reset,SEPARATOR.join(value)))
        if type(value) is list:
          for item in value:
            if type(item) is dict:
              out = ""
              for field in item:
                out += "%s%s%s: %s, " % (c_magenta,field,c_reset,item[field])
              print("%s%-35s - %s %s" % (c_yellow," ",c_reset,out))
          # print("%s%-35s = %s %s" % (c_green,field,c_reset,SEPARATOR.join(value)))
    else:
      print("%s%-35s = %s %s" % (c_green,field,c_reset,value))

def print_srvinfo(my_object,color_opt='',section=''):
  if section:
    browse_object(my_object,color_opt,section)
  else:
    for section in my_object:
      browse_object(my_object,color_opt,section)
  print("\n")

#######################################################################################################################
#
# Main
#
##

# Check args ##########################################################################################################

def main():
  OUTFORMAT = 'text' # Global used in function: do_shodan
  target = ret = what = color_opt = ''
  try:
    if sys.argv[1] == '-h':
      usage()
  except:
    usage()

  if len(sys.argv) >= 3:
    if sys.argv[1] == '-j':
      OUTFORMAT = 'json'
      target = sys.argv[2]
    elif sys.argv[1] == '-I':
      ret = import_json(sys.argv[2])
      target = '-'
    elif sys.argv[1] == '-p':
      OUTFORMAT = 'python'
      target = sys.argv[2]
    elif sys.argv[1] == '-t':
      OUTFORMAT = 'text'
      target = sys.argv[2]
    elif sys.argv[1] == '-n':
      OUTFORMAT = 'nocolor'
      target = sys.argv[2]
    else:
      target = sys.argv[1]
      what = sys.argv[2].upper()
  elif len(sys.argv) == 2:
    target = sys.argv[1]
  if len(sys.argv) == 4:
    what = sys.argv[3].upper()

  check_tools()

  if not target:
    usage()

  if not ret:
    ret = srvinfo(target)

  if OUTFORMAT == 'json':
    ret = json.dumps(ret, sort_keys=True, indent=4)
    print(ret)
  elif OUTFORMAT == 'python':
    print(ret)
  elif OUTFORMAT == 'nocolor':
    print_srvinfo(ret,'n',section=what)
  else:
    print_srvinfo(ret,color_opt=color_opt,section=what)



# Main ################################################################################################################

main()

