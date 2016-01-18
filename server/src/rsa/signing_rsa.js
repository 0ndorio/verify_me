"use strict";

import util, { assert, BigInteger } from "verifyme_utility"

/**
 * Signs the given blinded message.
 *
 * @param {string} message
 *    The message to sign.
 * @param {KeyManager} key_manager
 *    The {KeyManager} containing the ecc based key
 *    that will be used to sign the message.
 * @returns {string}
 *    The signed message.
 */
export default function sign(message, key_manager)
{
  assert(util.isString(message));
  assert(util.isKeyManagerForRsaSign(key_manager));

  const key_pair = key_manager.get_primary_keypair();

  const m = new BigInteger(message, 32);
  const n = key_pair.pub.n;
  const d = key_pair.priv.d;

  return m.modPow(d, n).toRadix(32);
}