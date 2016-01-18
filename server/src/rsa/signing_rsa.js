"use strict";

import { assert, BigInteger, check } from "verifyme_utility"

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
  assert(check.isString(message));
  assert(check.isKeyManagerForRsaSign(key_manager));

  const key_pair = key_manager.get_primary_keypair();

  const m = new BigInteger(message, 32);
  const n = key_pair.pub.n;
  const d = key_pair.priv.d;

  return m.modPow(d, n).toRadix(32);
}