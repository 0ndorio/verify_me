"use strict";

import { BigInteger } from "../../node_modules/kbpgp/lib/bn"
import { KeyManager } from "kbpgp"
import { Point } from "keybase-ecurve"

import util, { assert } from "verifyme_utility"

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
  assert(util.isKeyManager(key_manager));

  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;
  const n = curve.n;
  const G = curve.G;

  const p = await generateRandomScalar(curve);
  const q = await generateRandomScalar(curve);

  const p_inv = p.modInverse(n);

  const P = G.multiply(p_inv);
  assert(curve.isOnCurve(P));

  const Q = G.multiply(p_inv).multiply(q);
  assert(curve.isOnCurve(Q));

  return {p, P, q, Q};
}

/**
 * Generate a random scalar k.
 *
 * k is in range [1, n-1] where n is the prime number defining
 * the order of the givens curves base point.
 *
 * @param {Curve} curve
 *    The curve we use to generate the random scalar value.
 * @returns {Promise}
 *    The promise of a {BigInteger} scalar [1, n-1]
 */
async function generateRandomScalar(curve)
{
  assert(util.isCurve(curve));

  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => resolve(k))
  );
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
  assert(util.isString(message));
  assert(util.isKeyManagerForEcdsaSign(key_manager));
  assert(util.isObject(secret_scalars));
  assert(secret_scalars.hasOwnProperty("p") && util.isBigInteger(secret_scalars.p));
  assert(secret_scalars.hasOwnProperty("q") && util.isBigInteger(secret_scalars.q));


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