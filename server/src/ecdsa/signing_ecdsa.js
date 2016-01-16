"use strict";

import { BigInteger } from "../../node_modules/kbpgp/lib/bn"
import { KeyManager } from "kbpgp"
import { Point } from "keybase-ecurve"

/// TODO
async function prepareBlinding(key_manager)
{
  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;
  const n = curve.n;
  const G = curve.G;

  const p = await generateRandomScalar(curve);
  const q = await generateRandomScalar(curve);

  const p_inv = p.modInverse(n);

  const P = G.multiply(p_inv);
  const Q = G.multiply(p_inv).multiply(q);

  if(!curve.isOnCurve(P))
  {
   throw new Error("P not on curve");
  }

  if (!curve.isOnCurve(Q)) {
    throw new Error("Q not on curve");
  }

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
  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => resolve(k))
  );
}

/// TODO
function sign(message, secret_scalars, key_manager)
{
  if (typeof message !== "string") {
    throw new Error("message is not of type string");
  }

  if (secret_scalars.p.constructor.name !== "BigInteger") {
    throw new Error("secret scalar p is missing");
  }

  if (secret_scalars.q.constructor.name !== "BigInteger") {
    throw new Error("secret scalar q is missing");
  }

  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

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