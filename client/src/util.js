"use strict";

import { BigInteger } from "../node_modules/kbpgp/lib/bn"
import * as kbpgp from "kbpgp"

module.exports = {

  BigInteger: BigInteger,

  /**
   * Converts the binary data in BigInteger into a byte string.
   *
   * @param bigInteger
   *    {BigInteger} to convert into byte string.
   * @returns {string|null}
   *    {string} representation of the given {BigInteger} or null
   *    if input parameter is no {BigInteger}.
   */
  bigInt2Bytes: function(bigInteger)
  {
    var result = null;
    if (bigInteger instanceof BigInteger) {

      // toBuffer() called on 0 creates an empty buffer which is represented
      // by an empty string. To avoid this we enforce a buffer of minimum size 1.
      var buffer_size = (bigInteger.byteLength() === 0) ? 1 : bigInteger.byteLength();
      result = bigInteger.toBuffer(buffer_size).toString("binary");
    }

    return result;
  },

  /// TODO
  bytes2BigInt: function(byte_string)
  {
    return BigInteger.fromBuffer(new kbpgp.Buffer(byte_string, "binary"));
  },

  /// bytes to hex
  bytes2hex: function(byte_string)
  {
    if (!this.isString(byte_string)) {
      return "";
    }

    var buffer = new kbpgp.Buffer(byte_string, "binary");
    return buffer.toString("hex");
  },

  /// hex to bytes
  hex2bytes: function(hex_as_string)
  {
    if (!this.isString(hex_as_string)) {
      return "";
    }

    if ((hex_as_string.length % 2) === 1) {
      hex_as_string = "0" + hex_as_string;
    }

    var bytes = new kbpgp.Buffer(hex_as_string, "hex");
    return bytes.toString("binary");
  },

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

    var key = null;
    kbpgp.KeyManager.import_from_armored_pgp({ armored: key_as_string },
      function(err, key_manager) {
        if (!err) { key = key_manager; }
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

    var key_arguments = {
      e: 65537,
      nbits: primeBitLength * 2
    };

    return new Promise(function(resolve, reject) {
      kbpgp.asym.RSA.generate(key_arguments, function(err, key) {
        if (err) {
          reject(err);
        } else {
          resolve([key.priv.p, key.priv.q]);
        }
      });
    });
  },

  /// TODO
  generateBlindingFactor: function(bitLength)
  {
    if (!this.isInteger(bitLength)) {
      return Promise.reject("The prime bit length is no integer but a '" + bitLength + "'");
    } else if(!((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384)) {
      return Promise.reject("The prime bit length must be a multiple of 8 bits and >= 256 and <= 16384");
    }

    var sub_prime_length = Math.floor(bitLength / 2);
    return this.generateTwoPrimeNumbers(sub_prime_length)
      .then(function(primes) {
        return primes[0].multiply(primes[1]);
      });
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

    var textarea = document.getElementById(text_area_name);

    var content = null;
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
    var digest = null;
    if (this.isString(message)) {
      var hash_buffer = kbpgp.hash.SHA512(new kbpgp.Buffer(message));
      digest = BigInteger.fromBuffer(hash_buffer);
    }

    return digest;
  },

  /// Converts an integer in a {BigInteger}.
  ///
  /// @parameter {number} integer
  ///   The integer to convert into a BigInteger object.
  /// @return
  ///   A {BigInteger} object IF input is a valid integer ELSE {null}
  int2BigInt: function(integer)
  {
    var bigInt = null;

    if (this.isInteger(integer)) {
      bigInt = new BigInteger(integer.toString());
    }

    return bigInt;
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

  /// Checks if the given input is the result of a successful key read operation.
  isKeyReadSuccessful: function(key)
  {
    return this.isObject(key)
      && !Array.isArray(key)
      && !key.hasOwnProperty("err")
      && key.hasOwnProperty("keys");
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
  isOpenPGPKey: function(key)
  {
    return (key instanceof kbpgp.KeyManager);
  },

  /// Validates if the input parameter is a string.
  isString: function(string)
  {
    return (typeof string === "string");
  },

  /// TODO
  str2BigInt: function(string)
  {
    if (!this.isString(string)) {
      return null;
    }

    var buffer = new kbpgp.Buffer(string, "ascii");
    return BigInteger.fromBuffer(buffer);
  }
};
