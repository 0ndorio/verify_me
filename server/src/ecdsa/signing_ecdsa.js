"use strict";

import { BigInteger } from "../../node_modules/kbpgp/lib/bn"
import { KeyManager } from "kbpgp"
import { Point } from "keybase-ecurve"

/**
 * Prepare ECDSA based blinding.
 *
 *  - compute random scalar k
 *  - calculate related point Ŕ
 *  - if Ŕ is on curve and ŕ (mod n) is not zero return k and Ŕ
 *
 * @param {KeyManager} key_manager
 *    The public key container.
 * @returns {{k: BigInteger, Ŕ: Point}}
 *    The secret signature scalar value k and the related point Ŕ.
 */
async function prepare_blinding(key_manager)
{
  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;

  let k = BigInteger.ZERO;
  let Ŕ = BigInteger.ZERO;
  let ŕ = BigInteger.ZERO;

  do {

    k = await generate_random_scalar(curve);
    Ŕ = curve.G.multiply(k);
    ŕ = Ŕ.affineX.mod(curve.n);

  } while (!curve.isOnCurve(Ŕ) || ŕ.compareTo(BigInteger.ZERO) === 0);

  return {k, Ŕ};
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
async function generate_random_scalar(curve)
{
  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => resolve(k))
  );
}

/// TODO
function sign_blinded_message(message, secret_scalar, key_manager)
{
  if (typeof message !== "string") {
    throw new Error("message is not of type string");
  }

  if (secret_scalar.constructor.name !== "BigInteger") {
    throw new Error("secret scalar is missing");
  }

  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

  // prepare
  const key_pair = key_manager.get_primary_keypair();
  const curve = key_pair.pub.curve;
  const ḿ = new BigInteger(message, 32);
  const k = secret_scalar;

  // restore Ŕ
  const Ŕ = curve.G.multiply(k);
  const ŕ = Ŕ.affineX.mod(curve.n);

  // calculate signed_blinded_message ś
  const signed_blinded_message = key_pair.priv.x.multiply(ŕ).add(k.multiply(ḿ)).mod(curve.n);
  return signed_blinded_message.toRadix(32);
}

const signing_ecdsa_api = {
  prepare: prepare_blinding,
  sign: sign_blinded_message
};

export default signing_ecdsa_api;