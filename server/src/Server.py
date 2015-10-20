import io
import struct
import sys
import os

import tornado.ioloop
import tornado.web

from ..lib.OpenPGPPseudonyms import crypto
from ..lib.OpenPGPPseudonyms.OpenPGP import messages, packets

# --- Settings ---

root = os.path.dirname(os.path.abspath(__file__))

public_key_path = '../lib/OpenPGPPseudonyms/tests/testdata/foobar-bar.com_public_2048.txt'
public_key_string = open(root + "/" + public_key_path, "r").read()
public_key = messages.fromRadix64(public_key_string)

secret_key_path = '../lib/OpenPGPPseudonyms/tests/testdata/foobar-bar.com_secret_2048.txt'
secret_key_string = open(root + "/" + secret_key_path, "r").read()
secret_key = messages.fromRadix64(secret_key_string)

# ----------------

class MainHandler(tornado.web.RequestHandler):
   def get(self):

      self.render("../../client/index.html", public_key = public_key_string)

   def post(self):

      data = tornado.escape.json_decode(self.request.body)

      blinded_message = int(data["message"], 10)
      token_hash = data["token_hash"]

      TAG_SECKEY = packets.SecretKeyPacket.TAG

      d = secret_key.packets[TAG_SECKEY].d.value
      n = secret_key.packets[TAG_SECKEY].n.value
      signed_blinded_message = crypto.rsaSign(blinded_message, d, n)

      self.set_header("Content-Type", "text/plain")
      self.write(str(signed_blinded_message))

settings = {
   "static_path": os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "client"),
}

application = tornado.web.Application([
   (r"/", MainHandler),
   (r"/(js/.*)", tornado.web.StaticFileHandler, dict(path=settings["static_path"]))
], **settings)

if __name__ == "__main__":
   application.listen(8888)
   tornado.ioloop.IOLoop.instance().start()
