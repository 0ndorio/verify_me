"use strict";

import fs from "fs"

import util, { assert } from "verifyme_utility"
import config from "./config"
const rsa = config.keys.rsa;
const ecc = config.keys.ecc;

/**
 * Loads and unlocks a key pair.
 *
 * @param {string} public_key_path
 *    Path to the public key.
 * @param {string} private_key_path
 *    Path to the private key.
 * @param {string} passphrase
 *    Passphrase to unlock the private key.
 * @returns {Promise.<KeyManager>}
 *    The promise of a {KeyManager] that contains
 *    the key objects.
 */
async function loadKey(public_key_path, private_key_path, passphrase = null)
{
  assert(util.isString(public_key_path));
  assert(util.isString(private_key_path));

  const public_key_string = fs.readFileSync(public_key_path, "utf-8");
  const private_key_string = fs.readFileSync(private_key_path, "utf-8");

  const key_manager = await util.generateKeyFromString(public_key_string);
  await mergePrivateKeyIntoKeyManager(key_manager, private_key_string);

  if (passphrase) {
    assert(util.isString(passphrase));
    await unlockPrivateKeyInKeyManager(key_manager, passphrase);
  }

  return key_manager;
}

/**
 * Helper to merge a private key into a given public key containing {KeyManager}.
 *
 * @param {KeyManager} key_manager
 *    A public key containing {KeyManager}.
 * @param {string} private_key_string
 *    Path to the private key.
 * @returns {Promise.<KeyManager>}
 *    Promise of a {KeyManager} containing both keys.
 */
function mergePrivateKeyIntoKeyManager(key_manager, private_key_string)
{
  assert(util.isKeyManager(key_manager));
  assert(util.isString(private_key_string));

  return new Promise((resolve, reject) => {

    key_manager.merge_pgp_private({
      armored: private_key_string
    }, (err) => {
      if (err) reject(err);
      else resolve(key_manager);
    });
  });
}

/**
 * Unlocks a a password secured private key.
 *
 * @param {KeyManager} key_manager
 *    The {KeyManager} that contains the locked key.
 * @param {string} passphrase
 *    The password to unlock the key.
 * @returns {Promise.<*>}
 *    The promise that the key is unlocked.
 */
function unlockPrivateKeyInKeyManager(key_manager, passphrase)
{
  assert(util.isKeyManager(key_manager));
  assert(util.isString(passphrase));

  return new Promise((resolve, reject) => {

    key_manager.unlock_pgp({ passphrase }, (err) => {
      if (err) reject(err);
      else resolve(key_manager);
    });
  });
}

const rsa_promise = loadKey(rsa.public_key, rsa.private_key, rsa.passphrase);
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