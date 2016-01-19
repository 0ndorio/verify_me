"use strict";

import * as kbpgp from "kbpgp"
import { BigInteger, Buffer, Curve, KeyManager, Point, Tags } from "./types"

/**
 * Client runtime assert.
 * Throws if the given condition validates to {false} else nothing happens.
 *
 * @param {boolean} condition
 *    Validated condition.
 * @param {string|null} message
 *    Custom assert message.
 */
function assert(condition, message)
{
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

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

    assert(isString(key_as_string), "Input parameter is not of type string.");

    KeyManager.import_from_armored_pgp({ armored: key_as_string }, (err, key_manager) => {
      if (err) { reject(err); }
      else {
        resolve(key_manager);
      }
    });
  });
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

    assert(isInteger(primeBitLength),
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
 * Generates a blinding factor for the rsa blinding algorithm.
 *
 * @param {number} bitLength
 *    The target blinding factor length in bit.
 * @returns {BigInteger}
 *    the requested blinding factor.
 */
async function generateRsaBlindingFactor(bitLength)
{
  assert(isInteger(bitLength),
    "The blinding factor bit length is no integer but a '" + bitLength + "'");
  assert((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384,
    "The blinding factor bit length must be a multiple of 8 bits and >= 256 and <= 16384");

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
function hashMessageSha512(message)
{
  assert(isString(message));

  const hash_buffer = kbpgp.hash.SHA512(new Buffer(message));
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
  return isObject(object) && (object instanceof Buffer);
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
  return isObject(object) && (object instanceof Curve);
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
  return (key_manager instanceof KeyManager)
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

  const tags = Tags.public_key_algorithms;
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
  const tags = Tags.public_key_algorithms;

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
  generateRsaBlindingFactor,
  generateKeyFromString,
  generateTwoPrimeNumbers,
  hashMessageSha512,
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
  isString
};

export default util_api;
export { assert };
