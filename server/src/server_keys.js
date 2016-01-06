"use strict";

import fs from "fs"
import * as kbpgp from "kbpgp"

/// Converts a given armored key string into a kbpgp {KeyManager} object.
function generateKeyFromString(key_as_string)
{
  if (typeof key_as_string !== "string") {
    Promise.reject(new Error("Wrong typed input to key generation."));
  }

  return new Promise((resolve, reject) => {
    kbpgp.KeyManager.import_from_armored_pgp({ armored: key_as_string }, (err, key_manager) => {
      if (err) { reject(err); }
      else {
        resolve(key_manager);
      }
    });
  });
}

/// TODO
function loadKey(file_path)
{
  const key_string = fs.readFileSync(file_path, "utf-8");
  return generateKeyFromString(key_string);
}

/// Keys
const base_dir = __dirname + "/../../client/test/sample_keys/";

export const rsa_private_key = loadKey(base_dir + "rsa_1024_priv.asc");
export const rsa_public_key = loadKey(base_dir + "rsa_1024_pub.asc");

export const ecc_private_key = loadKey(base_dir + "ecc_nist_p_256_priv.asc");
export const ecc_public_key = loadKey(base_dir + "ecc_nist_p_256_pub.asc");