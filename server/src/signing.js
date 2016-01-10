"use strict";

import { KeyManager } from "kbpgp"
import { BigInteger } from "../node_modules/kbpgp/lib/bn"

import { rsa_promise, ecc_promise } from "./keys"

/// TODO
function sign_blinded_rsa_message(message, key_manager)
{
  if (typeof message !== "string") {
    throw new Error("message is not of type string");
  }

  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

  const key_pair = key_manager.get_primary_keypair();

  const m = new BigInteger(message, 16);
  const n = key_pair.pub.n;
  const d = key_pair.priv.d;

  return m.modPow(d, n).toRadix(16);
}

/// TODO
async function prepareEcdsaBlinding(key_manager)
{
  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;

  const rx = BigInteger.ZERO;
  do {

    const k = await generateRandomScalar(curve);
    const R = curve.G.multiply(k);
    assert(curve.isOnCurve(R));

  } while(0 === rx.compareTo(BigInteger.ZERO));

  return {k, R};
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
export function sign_blinded_ecdsa_message(message, key_manager)
{}

const signing_api = {
  prepareEcdsaBlinding,
  sign_blinded_rsa_message,
  sign_blinded_ecdsa_message
};

export default signing_api;
