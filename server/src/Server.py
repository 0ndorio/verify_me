import io
import struct
import sys
import os

import tornado.ioloop
import tornado.web

# RSA
from ..lib.OpenPGPPseudonyms import crypto
from ..lib.OpenPGPPseudonyms.OpenPGP import messages, packets

# ECC
import seccure

# --- Utility --------

def enter_password():
   print 'Passphrase needed for secret key'
   return raw_input('password: ')

def handle_rsa_request(blinded_message):
   print ("Handling RSA request for: ", blinded_message)

   SEC_TAG = packets.SecretKeyPacket.TAG
   package = rsa_secret_key.packets[SEC_TAG]

   d = package.d.value
   n = package.n.value

   return crypto.rsaSign(blinded_message, d, n)

def handle_ecdsa_request(blinded_message):
   print ("Handling ECDSA request for: ", blinded_message)
   return None

# --- Request Handling ---

class MainHandler(tornado.web.RequestHandler):
   def get(self):

      self.render("../../client/index.html", public_key = rsa_public_key_string)

   def post(self):

      data = tornado.escape.json_decode(self.request.body)

      blinded_message = int(data["message"], 16)
      token_hash = data["token_hash"]
      is_rsa_request = data["is_rsa"]

      if is_rsa_request:
         signed_blinded_message = handle_rsa_request(blinded_message)
      else:
         signed_blinded_message = handle_ecdsa_request(blinded_message)

      output = hex(signed_blinded_message).lstrip("0x").rstrip("L")

      self.set_header("Content-Type", "text/plain")
      self.write(output)

# --- Key Settings ---

root = os.path.dirname(os.path.abspath(__file__))

rsa_public_key_path = '../../keys/rsa_server.asc'
rsa_public_key_string = open(root + "/" + rsa_public_key_path, "r").read()
rsa_public_key = messages.fromRadix64(rsa_public_key_string)

rsa_secret_key_path = '../../keys/rsa_server_secret.asc'
rsa_secret_key_string = open(root + "/" + rsa_secret_key_path, "r").read()
rsa_secret_key = messages.fromRadix64(rsa_secret_key_string, enter_password)

#ecc_public_key_path = '../../keys/ecc_server.asc'
#ecc_public_key_string = open(root + "/" + ecc_public_key_path, "r").read()
#ecc_public_key = messages.fromRadix64(ecc_public_key_string)

#ecc_secret_key_path = '../../keys/ecc_server_secret.asc'
#ecc_secret_key_string = open(root + "/" + ecc_secret_key_path, "r").read()
#ecc_secret_key = messages.fromRadix64(ecc_secret_key_string, enter_password)

# --- Server Setup ---

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
