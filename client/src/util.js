"use strict";

var BigInteger = require("../node_modules/kbpgp/lib/bn").BigInteger;
var kbpgp = require("kbpgp");
var naive_is_prime = require("../node_modules/kbpgp/lib/primegen").naive_is_prime;

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

  /// bytes to hex
  bytes2hex: function(byte_string)
  {
    if (!this.isString(byte_string)) {
      return "";
    }

    var buffer = new kbpgp.Buffer(byte_string, "binary");
    return buffer.toString("hex");
  },

  /// TODO
  bytes2MPI: function(byte_string)
  {
    if (!this.isString(byte_string)) { return null; }

    return {
      data: new BigInteger(new kbpgp.Buffer(byte_string, "binary"))
    };
  },

  /// hex to bytes
  hex2bytes: function(hex_as_string)
  {
    if (!this.isString(hex_as_string)) {
      return "";
    }

    if (hex_as_string.length === 1) {
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
    } else if(!((primeBitLength % 8 === 0) && primeBitLength >= 256 && primeBitLength <= 16384)) {
      return Promise.reject("The prime bit length must be a multiple of 8 bits and >= 128 and <= 8192");
    }

    /// rsa.generate() requires a public exponent.
    /// This exponent has to be 3 or 65537 written in base 16.
    ///
    /// 3 => "3"
    /// 65537 => "10001"
    var public_exponent = "10001";
    var modulus_bit_length = primeBitLength * 2;

    var rsa = new kbpgp.crypto.publicKey.rsa();
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
      digest = kbpgp.hash.SHA512(new kbpgp.Buffer(message)).toString("binary");
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
    return this.isMPIWithData(mpi) && naive_is_prime(mpi.data);
  },

  /// TODO
  isMPIWithData: function(mpi)
  {
    return this.isObject(mpi) && (mpi.data instanceof BigInteger);
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
    var bigInt = null;
    if (this.isString(string) && /^[0-9]+$/.test(string)) {
      bigInt = new BigInteger(string);
    }

    return bigInt;
  }
};
