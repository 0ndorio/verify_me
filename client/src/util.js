"use strict";

import { BigInteger } from "../node_modules/kbpgp/lib/bn"
import { Point } from "keybase-ecurve"
import * as kbpgp from "kbpgp"

function assert(condition, message)
{
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

/// Converts a given armored key string into a kbpgp {KeyManager} object.
function generateKeyFromString(key_as_string)
{
  if (!isString(key_as_string)) {
    return Promise.reject(new Error("Input parameter is not of type string."));
  }

  return new Promise((resolve, reject) => {
    kbpgp.KeyManager.import_from_armored_pgp({ armored: key_as_string }, (err, key_manager) => {
      if (err) { reject(err); }
      else {
        resolve(key_manager);
      }
    });
  });
}

/// Generate two prime numbers with n bits using the rsa.generate()
/// in lack of a real generatePrime() method.
function generateTwoPrimeNumbers(primeBitLength)
{
  if (!isInteger(primeBitLength)) {
    return Promise.reject("The prime bit length is no integer but a '" + primeBitLength + "'");
  } else if(!((primeBitLength % 8 === 0) && primeBitLength >= 128 && primeBitLength <= 8192)) {
    return Promise.reject("The prime bit length must be a multiple of 8 bits and >= 128 and <= 8192");
  }

  const key_arguments = {
    e: 65537,
    nbits: primeBitLength * 2
  };

  return new Promise((resolve, reject) => {
    kbpgp.asym.RSA.generate(key_arguments, (err, key) => {
      if (err) {
        reject(err);
      }

      resolve([key.priv.p, key.priv.q]);
    });
  });
}

/// TODO
async function generateBlindingFactor(bitLength)
{
  if (!isInteger(bitLength)) {
    throw new Error("The prime bit length is no integer but a '" + bitLength + "'");
  } else if(!((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384)) {
    throw new Error("The prime bit length must be a multiple of 8 bits and >= 256 and <= 16384");
  }

  const sub_prime_length = Math.floor(bitLength / 2);
  let primes = await generateTwoPrimeNumbers(sub_prime_length);

  return primes[0].multiply(primes[1]);
}

/**
 * Hashes the given message with sha512 and returns the digest.
 *
 * @param {string} message
 *    Input parameter to hash.
 * @returns {BigInteger}
 *    Hash digest as {string} or {null} if input message is no string object.
 */
function hashMessage(message)
{
  if (!isString(message)) {
    return null;
  }

  const hash_buffer = kbpgp.hash.SHA512(new kbpgp.Buffer(message));
  return BigInteger.fromBuffer(hash_buffer);
}

/**
 * Checks if the given object is a {BigInteger}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {BigInteger}
 *    else {false}
 */
function isBigInteger(object)
{
  return isObject(object) && (object.constructor.name === BigInteger.name);
}

/**
 * Checks if the given object is a {Buffer}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Buffer}
 *    else {false}
 */
function isBuffer(object)
{
  return isObject(object) && (object instanceof kbpgp.Buffer);
}

/**
 * Checks if the given element is an ecc {Curve}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Curve}
 *    else {false}
 */
function isCurve(object)
{
  return isObject(object) && (object instanceof kbpgp.ecc.curves.Curve);
}

/**
 * Checks if the given element is a {function}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {function}
 *    else {false}
 */
function isFunction(object)
{
  return (typeof object === "function");
}

/**
 * Checks if the given element is an integer {number}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is an integer
 *    else {false}
 */
function isInteger(object)
{
  return (typeof object === "number") && (object % 1 === 0);
}

/**
 * Checks if the given element is an {object}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is an {object}
 *    else {false}
 */
function isObject(object)
{
  return object === Object(object);
}

/**
 * Checks if the given object is a valid {KeyManager}.
 *
 * @param {*} key_manager
 *
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager}
 *    else {false}.
 */
function isKeyManager(key_manager)
{
  return (key_manager instanceof kbpgp.KeyManager)
      && (key_manager.get_primary_keypair() !== null);
}

/**
 * Checks if the given object is a valid {KeyManager} which
 * contains a ECDSA based key_manager.
 *
 * @param {KeyManager} key_manager
 *    The object that is checked for the used algorithm.
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager} that can be
 *    used to sign based on the ECDSA algorithm else {false}.
 */
function isKeyManagerForEcdsaSign(key_manager)
{
  if (!isKeyManager(key_manager)) { return false; }

  const tags = kbpgp.const.openpgp.public_key_algorithms;
  const key_algorithm = key_manager.get_primary_keypair().get_type();

  return (key_algorithm === tags.ECDSA);
}

/**
 * Checks if the given object is a valid {KeyManager} which
 * contains a RSA or RSA_SIGN_ONLY based key_manager.
 *
 * @param {KeyManager} key_manager
 *    The object that is checked for the used algorithm.
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager} that can be used
 *    to sign based on the RSA algorithm else {false}.
 */
function isKeyManagerForRsaSign(key_manager)
{
  if (!isKeyManager(key_manager)) { return false; }

  const key_algorithm = key_manager.get_primary_keypair().get_type();
  const tags = kbpgp.const.openpgp.public_key_algorithms;

  return (key_algorithm === tags.RSA) || (key_algorithm === tags.RSA_SIGN_ONLY);
}

/**
 * Checks if the given element is a {Point}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Point}
 *    else {false}
 */
function isPoint(object)
{
  return isObject(object) && (object instanceof Point);
}

/**
 * Checks if the given element is a {string}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Point}
 *    else {false}
 */
function isString(object)
{
  return (typeof object === "string");
}

const util_api = {
  assert,
  BigInteger,
  generateBlindingFactor,
  generateKeyFromString,
  generateTwoPrimeNumbers,
  hashMessage,
  isBigInteger,
  isBuffer,
  isCurve,
  isFunction,
  isInteger,
  isKeyManager,
  isKeyManagerForEcdsaSign,
  isKeyManagerForRsaSign,
  isObject,
  isPoint,
  isString,
  Point,
  public_key_algorithms_tags: kbpgp.const.openpgp.public_key_algorithms
};

export default util_api;
export { assert, BigInteger, Point };