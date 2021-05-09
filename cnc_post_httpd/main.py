from threading import *
from terminal import *
import listener
import sys

###############################################################################
#
# Args
#
##

LIP = '127.0.0.1'
LPORT = 8000
VERBOSE=0

for index in range(len(sys.argv)):
  av = sys.argv[index]
  if av == '-i':
    LIP = sys.argv[index+1]
  if av == '-p':
    LPORT = int(sys.argv[index+1])

###############################################################################
#
# Main
#
##

cmd = ''

if __name__ == '__main__':

  terminal = Terminal()
  try:
    terminal_thread = Thread(target=terminal.cmdloop,)
    terminal_thread.start()
  except:
    print("\nTerminal component interrupted.")
    exit()

  print("Starting Web Server on {}:{}...".format(LIP,LPORT))
  try:
    listener.run()
  except KeyboardInterrupt:
    print("\nProcess aborted.")
    exit()

