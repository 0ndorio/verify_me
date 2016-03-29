"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var base_dir = __dirname + "/../../client";
var key_base_dir = base_dir + "/test/sample_keys";

exports.default = {

  client: {
    base_dir: base_dir
  },

  keys: {

    rsa: {

      public_key: key_base_dir + "/rsa_1024_pub.asc",
      private_key: key_base_dir + "/rsa_1024_priv.asc",
      passphrase: "verifyme"

    },

    ecc: {

      public_key: key_base_dir + "/ecc_nist_p_256_pub.asc",
      private_key: key_base_dir + "/ecc_nist_p_256_priv.asc",
      passphrase: "verifyme"

    }
  }
};