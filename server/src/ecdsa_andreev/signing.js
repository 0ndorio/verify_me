"use strict";

import { assert, BigInteger, check, Point, KeyManager, util } from "verifyme_utility"

/**
 * Prepares the ECDSA blinding algorithm through
 * the creation of request individual secret scalar
 * values and the related public points.
 *
 * @param {KeyManager} key_manager
 *    A {KeyManager} containing an ECC based key to
 *    extract the related curves public information.
 * @returns {{p: number, P: Point, q: number, Q: Point}}
 *    The request secret scalars p, q
 *    and the related public points P, Q.
 */
async function prepareBlinding(key_manager)
{
  assert(check.isKeyManager(key_manager));

  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;
  const n = curve.n;
  const G = curve.G;

  const p = await util.generateRandomScalar(curve);
  const q = await util.generateRandomScalar(curve);

  const p_inv = p.modInverse(n);

  const P = G.multiply(p_inv);
  assert(curve.isOnCurve(P));

  const Q = G.multiply(p_inv).multiply(q);
  assert(curve.isOnCurve(Q));

  return {p, P, q, Q};
}

/**
 * Signs the given blinded message.
 *
 * @param {string} message
 *    The message to sign.
 * @param {object.<number, number>}secret_scalars
 *    The scalar values created during initialization.
 * @param {KeyManager} key_manager
 *    The {KeyManager} containing the ecc based key
 *    that will be used to sign the message.
 * @returns {string}
 *    The signed message.
 */
function sign(message, secret_scalars, key_manager)
{
  assert(check.isString(message));
  assert(check.isKeyManagerForEcdsaSign(key_manager));
  assert(check.isObject(secret_scalars));
  assert(secret_scalars.hasOwnProperty("p") && check.isBigInteger(secret_scalars.p));
  assert(secret_scalars.hasOwnProperty("q") && check.isBigInteger(secret_scalars.q));


  const public_key_package = key_manager.get_primary_keypair().pub;
  const n = public_key_package.curve.n;

  const m = new BigInteger(message, 32);
  const p = secret_scalars.p;
  const q = secret_scalars.q;

  const signed_blinded_message = p.multiply(m).add(q).mod(n);
  return signed_blinded_message.toRadix(32);
}

const signing_ecdsa_api = {
  prepare: prepareBlinding,
  sign: sign
};

export default signing_ecdsa_api;