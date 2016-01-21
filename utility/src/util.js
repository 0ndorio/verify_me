"use strict";

import * as kbpgp from "kbpgp"

import check, { assert } from "./check"
import { BigInteger, Curve, KeyManager } from "./types"

/**
 * Converts a given armored key string into a kbpgp {KeyManager} object.
 *
 * @param {string} key_as_string
 *    An ascii armored key string.
 * @returns {Promise}
 *    The promise of a {KeyManager} object.
 */
function generateKeyFromString(key_as_string)
{
  return new Promise((resolve, reject) => {

    assert(check.isString(key_as_string), "Input parameter is not of type string.");

    KeyManager.import_from_armored_pgp({ armored: key_as_string }, (err, key_manager) => {
      if (err) { reject(err); }
      else {
        resolve(key_manager);
      }
    });
  });
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
  assert(check.isCurve(curve));

  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => {

        // assert [1, n-1]
        assert(k.compareTo(BigInteger.ZERO) >= 0);
        assert(k.compareTo(curve.n) < 0);

        resolve(k);
      })
  );
}

/**
 * Generates a blinding factor for the rsa blinding algorithm.
 *
 * @param {number} bitLength
 *    The target blinding factor length in bit.
 * @returns {BigInteger}
 *    the requested blinding factor.
 */
async function generateRsaBlindingFactor(bitLength)
{
  assert(check.isInteger(bitLength),
    "The blinding factor bit length is no integer but a '" + bitLength + "'");
  assert((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384,
    "The blinding factor bit length must be a multiple of 8 bits and >= 256 and <= 16384");

  const sub_prime_length = Math.floor(bitLength / 2);
  let primes = await generateTwoPrimeNumbers(sub_prime_length);

  return primes[0].multiply(primes[1]);
}

/**
 * Generate two prime numbers with n bits using the rsa.generate()
 * in lack of a real generatePrime() method.
 *
 * @param {number} primeBitLength
 *    The target prime number length in bit.
 * @returns {Promise}
 *    The promise of two prime numbers with the requesterd bit length.
 */
function generateTwoPrimeNumbers(primeBitLength)
{
  return new Promise((resolve, reject) => {

    assert(check.isInteger(primeBitLength),
      "The prime bit length is no integer but a '" + primeBitLength + "'");
    assert((primeBitLength % 8 === 0) && primeBitLength >= 128 && primeBitLength <= 8192,
      "The prime bit length must be a multiple of 8 bits and >= 128 and <= 8192");

    const key_arguments = {
      e: 65537,
      nbits: primeBitLength * 2
    };

    kbpgp.asym.RSA.generate(key_arguments, (err, key) => {
      if (err) {
        reject(err);
      }

      resolve([key.priv.p, key.priv.q]);
    });
  });
}

/**
 * Hashes the given message with sha512 and returns the digest.
 *
 * @param {BigInteger} message
 *    Input parameter to hash.
 * @returns {BigInteger}
 *    Hash digest as {string} or {null} if input message is no string object.
 */
function calculateSha512(message)
{
  assert(check.isBigInteger(message));

  const hash_buffer = kbpgp.hash.SHA512(message.toBuffer());
  return BigInteger.fromBuffer(hash_buffer);
}

const util_api = {
  generateKeyFromString,
  generateRandomScalar,
  generateRsaBlindingFactor,
  generateTwoPrimeNumbers,
  calculateSha512
};

export default util_api;