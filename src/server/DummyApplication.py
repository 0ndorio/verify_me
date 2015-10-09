import tornado.ioloop
import tornado.web

import io
import sys
import os

from lib.OpenPGPPseudonyms.OpenPGP import messages

class MainHandler(tornado.web.RequestHandler):
   def get(self):

      root = os.path.dirname(os.path.abspath(__file__))
      path = 'lib/OpenPGPPseudonyms/tests/testdata/foobar-bar.com_public_2048.txt'

      radix64 = open(root + '/' + path, 'r').read()
      m = messages.fromRadix64(radix64)

      self.write(m.__str__())

application = tornado.web.Application([
   (r"/", MainHandler),
])

if __name__ == "__main__":
   application.listen(8888)
   tornado.ioloop.IOLoop.instance().start()
