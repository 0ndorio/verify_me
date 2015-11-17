"use strict";

var BigInteger = require("../node_modules/openpgp/src/crypto/public_key/jsbn");
var openpgp = require("openpgp");

module.exports = {

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
      result = openpgp.util.bin2str(bigInteger.toByteArray());
    }

    return result;
  },

  /// bytes to hex
  bytes2hex: function(byte_string)
  {
    var hex_string = "";
    if (this.isString(byte_string)) {
      hex_string = openpgp.util.hexstrdump(byte_string);
    }

    return hex_string;
  },

  /// TODO
  bytes2MPI: function(byte_string)
  {
    if (!this.isString(byte_string)) { return null; }

    var mpi = new openpgp.MPI();
    mpi.fromBytes(byte_string);

    return mpi;
  },

  /// hex to bytes
  hex2bytes: function(hex_as_string)
  {
    var byte_string = "";
    if (this.isString(hex_as_string)) {
      byte_string = openpgp.util.hex2bin(hex_as_string);
    }

    return byte_string;
  },

  /// Converts a given armored key string into a openpgp key object.
  ///
  /// @param {string} key_as_string
  ///      The armored key.
  /// @return
  ///      {object} containing the keys represented by the armored key or
  ///      {null} if sth. went wrong during conversion.
  generateKeyFromString: function(key_as_string)
  {
    if (!this.isString(key_as_string)) { return null; }

    var key = openpgp.key.readArmored(key_as_string);
    if (!this.isKeyReadSuccessful(key)) {
      key = null;
    }

    return key;
  },

  /// Generate two prime numbers with n bits using the rsa.generate()
  /// in lack of a real generatePrime() method.
  generateTwoPrimeNumbers: function(primeBitLength)
  {
    if (!this.isInteger(primeBitLength)) {
      return Promise.reject("pimeBitLength no integer but '" + primeBitLength + "'");
    }

    /// rsa.generate() requires a public exponent.
    /// This exponent has to be 3 or 65537 written in base 16.
    ///
    /// 3 => "3"
    /// 65537 => "10001"
    var public_exponent = "10001";
    var modulus_bit_length = primeBitLength * 2;

    var rsa = new openpgp.crypto.publicKey.rsa();
    return rsa
      .generate(modulus_bit_length, public_exponent)
      .then(function(key) {
        return [key.q, key.p];
      })
      .catch(function(error) {
        throw new Error("Something went wrong during prime number generation (" + error + ") . Please retry.");
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
   * @returns {string}
   *    Hash digest as {string} or {null} if input message is no string object.
   */
  hashMessage: function(message)
  {
    var digest = null;
    if (this.isString(message)) {
      digest = openpgp.crypto.hash.sha512(message);
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
    return (bigInteger instanceof BigInteger);
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

  /// Validates if the input parameter is probably a prime MPI.
  isMPIProbablyPrime: function(mpi)
  {
    return this.isMPIWithData(mpi) && (mpi.toBigInteger().isProbablePrime());
  },

  /// TODO
  isMPIWithData: function(mpi)
  {
    return this.isObject(mpi)
      && (mpi instanceof openpgp.MPI)
      && (mpi.data instanceof BigInteger);
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
    return (key instanceof openpgp.key.Key);
  },

  /// Validates if the input parameter is a string.
  isString: function(string)
  {
    return (typeof string === "string");
  },

  /// TODO
  str2BigInt: function(string)
  {
    var bigInt = null;
    if (this.isString(string) && /^[0-9]+$/.test(string)) {
      bigInt = new BigInteger(string);
    }

    return bigInt;
  }
};
