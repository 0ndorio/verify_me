"use strict";

import { BigInteger, nbi, nbs } from "../node_modules/kbpgp/lib/bn"
import { Point } from "keybase-ecurve"
import * as kbpgp from "kbpgp"

module.exports = {

  BigInteger: BigInteger,
  Point: Point,
  public_key_algorithms_tags: kbpgp.const.openpgp.public_key_algorithms,

  assert: function (condition, message)
  {
    if (!condition) {
      throw new Error(message || "Assertion failed");
    }
  },

  /// Converts a given armored key string into a kbpgp {KeyManager} object.
  generateKeyFromString: function(key_as_string)
  {
    if (!this.isString(key_as_string)) {
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
  },

  /// Generate two prime numbers with n bits using the rsa.generate()
  /// in lack of a real generatePrime() method.
  generateTwoPrimeNumbers: function(primeBitLength)
  {
    if (!this.isInteger(primeBitLength)) {
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
  },

  /// TODO
  generateBlindingFactor: async function(bitLength)
  {
    if (!this.isInteger(bitLength)) {
      throw new Error("The prime bit length is no integer but a '" + bitLength + "'");
    } else if(!((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384)) {
      throw new Error("The prime bit length must be a multiple of 8 bits and >= 256 and <= 16384");
    }

    const sub_prime_length = Math.floor(bitLength / 2);
    let primes = await this.generateTwoPrimeNumbers(sub_prime_length);

    return primes[0].multiply(primes[1]);
  },

  /**
   * Hashes the given message with sha512 and returns the digest.
   *
   * @param {string} message
   *    Input parameter to hash.
   * @returns {BigInteger}
   *    Hash digest as {string} or {null} if input message is no string object.
   */
  hashMessage: function(message)
  {
    if (!this.isString(message)) {
      return null;
    }

    const hash_buffer = kbpgp.hash.SHA512(new kbpgp.Buffer(message));
    return BigInteger.fromBuffer(hash_buffer);
  },

  /**
   * Checks if the given object is a {BigInteger}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {BigInteger}
   *    else {false}
   */
  isBigInteger: function(object)
  {
    return this.isObject(object) && (object.constructor.name === BigInteger.name);
  },

  /**
   * Checks if the given object is a {Buffer}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {Buffer}
   *    else {false}
   */
  isBuffer: function (object)
  {
    return this.isObject(object) && (object instanceof kbpgp.Buffer);
  },

  /**
   * Checks if the given element is an ecc {Curve}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {Curve}
   *    else {false}
   */
  isCurve: function(object)
  {
    return this.isObject(object) && (object instanceof kbpgp.ecc.curves.Curve);
  },

  /**
   * Checks if the given element is a {function}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {function}
   *    else {false}
   */
  isFunction: function(object)
  {
    return (typeof object === "function");
  },

  /**
   * Checks if the given element is an integer {number}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is an integer
   *    else {false}
   */
  isInteger: function(object)
  {
    return (typeof object === "number") && (object % 1 === 0);
  },

  /**
   * Checks if the given element is an {object}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is an {object}
   *    else {false}
   */
  isObject: function(object)
  {
    return object === Object(object);
  },

  /**
   * Checks if the given object is a valid {KeyManager}.
   *
   * @param {*} key_manager
   *
   * @returns {boolean}
   *    {true} if the given object is a {KeyManager}
   *    else {false}.
   */
  isKeyManager: function(key_manager)
  {
    return (key_manager instanceof kbpgp.KeyManager)
        && (key_manager.get_primary_keypair() !== null);
  },

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
  isKeyManagerForEcdsaSign(key_manager)
  {
    if (!this.isKeyManager(key_manager)) { return false; }

    const tags = this.public_key_algorithms_tags;
    const key_algorithm = key_manager.get_primary_keypair().get_type();

    return (key_algorithm === tags.ECDSA);
  },

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
  isKeyManagerForRsaSign(key_manager)
  {
    if (!this.isKeyManager(key_manager)) { return false; }

    const key_algorithm = key_manager.get_primary_keypair().get_type();
    const tags = this.public_key_algorithms_tags;

    return (key_algorithm === tags.RSA) || (key_algorithm === tags.RSA_SIGN_ONLY);
  },

  /**
   * Checks if the given element is a {Point}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {Point}
   *    else {false}
   */
  isPoint: function(object)
  {
    return this.isObject(object) && (object instanceof Point);
  },

  /**
   * Checks if the given element is a {string}.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the given element is a {Point}
   *    else {false}
   */
  isString: function(object)
  {
    return (typeof object === "string");
  }
};
