"use strict";

import { BigInteger, nbi, nbs } from "../node_modules/kbpgp/lib/bn"
import * as kbpgp from "kbpgp"

module.exports = {

  BigInteger: BigInteger,

  /// Converts a given armored key string into a kbpgp key object.
  ///
  /// @param {string} key_as_string
  ///      The armored key.
  /// @return
  ///      {kbpgp.KeyManager} containing the keys represented by the armored key or
  ///      {null} if sth. went wrong during conversion.
  generateKeyFromString: function(key_as_string)
  {
    if (!this.isString(key_as_string)) { return null; }

    /// TODO: unsafe due to timing issues ... refactore to Promise
    let key = null;
    kbpgp.KeyManager.import_from_armored_pgp(
      { armored: key_as_string },
      (err, key_manager) => { if (!err) { key = key_manager; }
    });

    return key;
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

  /// Loads content from textarea with specific id.
  ///
  /// @param {string} text_area_name
  ///      id of the requested text area
  /// @return
  ///      {string} if text area id is valid,
  ///      else {null}
  getTextAreaContent: function(text_area_name)
  {
    if (!this.isString(text_area_name)) { return null; }

    const textarea = document.getElementById(text_area_name);

    let content = null;
    if (textarea !== null) {
      content = textarea.value;
    }

    return content;
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

  /// TODO
  isBigInteger: function(bigInteger)
  {
    return this.isObject(bigInteger) && (bigInteger.constructor.name === BigInteger.name);
  },

  /// TODO
  isInteger: function(integer)
  {
    return (typeof integer === "number") && (integer % 1 === 0);
  },

  /**
   * Checks if the input parameter is an object.
   * @param {Object} object
   * @returns {boolean}
   */
  isObject: function(object)
  {
    return object === Object(object);
  },

  // TODO
  isKeyManager: function(key)
  {
    return (key instanceof kbpgp.KeyManager);
  },

  /// Validates if the input parameter is a string.
  isString: function(string)
  {
    return (typeof string === "string");
  }
};
