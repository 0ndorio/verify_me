"use strict";

import { BigInteger, nbi, nbs } from "../node_modules/kbpgp/lib/bn"
import * as kbpgp from "kbpgp"

module.exports = {

  BigInteger: BigInteger,

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
