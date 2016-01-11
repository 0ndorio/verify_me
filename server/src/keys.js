"use strict";

import fs from "fs"
import { KeyManager } from "kbpgp"

import config from "./config"

/// TODO
async function loadKey(public_key_path, private_key_path, passphrase = null)
{
  if (typeof public_key_path !== "string") {
    throw new Error("public_key_path is not of type string");
  }

  if (typeof private_key_path !== "string") {
    throw new Error("private_key_path is not of type string");
  }

  const public_key_string = fs.readFileSync(public_key_path, "utf-8");
  const private_key_string = fs.readFileSync(private_key_path, "utf-8");

  const key_manager = await import_public_key(public_key_string);
  await merge_private_key(key_manager, private_key_string);

  if (passphrase) {
    await unlock_private_key(key_manager, passphrase);
  }

  return key_manager;
}

/// TODO
function import_public_key(public_key_string)
{
  if (typeof public_key_string !== "string") {
    throw new Error("public_key_string is not of type string");
  }

  return new Promise((resolve, reject) => {

    KeyManager.import_from_armored_pgp({
      armored: public_key_string
    }, (err, key_manager) => {
      if (err) reject(err);
      else resolve(key_manager);
    });
  });
}

/// TODO
function merge_private_key(key_manager, private_key_string)
{
  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

  if (typeof private_key_string !== "string") {
    throw new Error("private_key_string is not of type string");
  }

  return new Promise((resolve, reject) => {

    key_manager.merge_pgp_private({
      armored: private_key_string
    }, (err) => {
      if (err) reject(err);
      else resolve(key_manager);
    });
  });
}

/// TODO
function unlock_private_key(key_manager, passphrase)
{
  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

  if (typeof passphrase !== "string") {
    throw new Error("passphrase is not of type string");
  }

  return new Promise((resolve, reject) => {

    key_manager.unlock_pgp({ passphrase }, (err) => {
      if (err) reject(err);
      else resolve(key_manager);
    });
  });
}

const rsa = config.keys.rsa
const rsa_promise = loadKey(rsa.public_key, rsa.private_key, rsa.passphrase);

const ecc = config.keys.ecc;
const ecc_promise = loadKey(ecc.public_key, ecc.private_key, ecc.passphrase);

let ecc_key = null;
let rsa_key = null;

const keys_api = {
  rsa_key,
  rsa_promise,
  ecc_key,
  ecc_promise
};

export default keys_api;