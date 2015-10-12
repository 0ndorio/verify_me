import io
import sys
import os

import tornado.ioloop
import tornado.web

from lib.OpenPGPPseudonyms.OpenPGP import messages

class MainHandler(tornado.web.RequestHandler):
   def get(self):

      root = os.path.dirname(os.path.abspath(__file__))
      path = 'lib/OpenPGPPseudonyms/tests/testdata/foobar-bar.com_public_2048.txt'

      public_key_string = open(root + '/' + path, 'r').read()
      self.render("../client/index.html", public_key = public_key_string)


settings = {
   "static_path": os.path.join(os.path.dirname(__file__), os.pardir, "client"),
}

application = tornado.web.Application([
   (r"/", MainHandler),
   (r"/(js/.*)", tornado.web.StaticFileHandler, dict(path=settings["static_path"]))
], **settings)

if __name__ == "__main__":
   application.listen(8888)
   tornado.ioloop.IOLoop.instance().start()
