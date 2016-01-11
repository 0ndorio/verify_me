"use strict";

import { BigInteger } from "../../node_modules/kbpgp/lib/bn"
import { Point } from "keybase-ecurve"
import * as kbpgp from "kbpgp"
const Curve = kbpgp.ecc.curves.Curve;

/**
 * Prepare ECDSA based blinding.
 *
 *  - compute random scalar k
 *  - calculate related point R
 *  - if R is on curve and Rx is not zero return k and R
 *
 * @param {KeyManager} key_manager
 *    The public key container.
 * @returns {{k: BigInteger, R: Point}}
 *    The secret signature scalar value k and the related point R.
 */
async function prepare_blinding(key_manager)
{
  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;

  let k = null;
  let R = null;

  do {
    k = await generate_random_scalar(curve);
    R = curve.G.multiply(k);

  } while((!curve.isOnCurve(R)) || (0 === R.affineX.compareTo(BigInteger.ZERO)));

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
async function generate_random_scalar(curve)
{
  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => resolve(k))
  );
}

const signing_ecdsa_api = {
  prepare_blinding
};

export default signing_ecdsa_api;