import tornado.ioloop
import tornado.web

import sys
import os
import io

from lib.OpenPGPBlinding.OpenPGP import *

class MainHandler(tornado.web.RequestHandler):
   def get(self):

      root = os.path.dirname(os.path.abspath(__file__))
      path = 'lib/OpenPGPBlinding/tests/testdata/foo-bar.com_secret_openpgp.txt'

      radix64 = open(root + '/' + path, 'r').read()
      m = messages.fromRadix64(radix64)
      self.write(m.__str__())

application = tornado.web.Application([
   (r"/", MainHandler),
])

if __name__ == "__main__":
   application.listen(8888)
   tornado.ioloop.IOLoop.instance().start()
