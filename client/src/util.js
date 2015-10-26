"use strict";

var BigInteger = require("../node_modules/openpgp/src/crypto/public_key/jsbn");
var openpgp = require("openpgp");

module.exports = {

  /// Converts an integer in a BigInteger.
  ///
  /// @parameter integer
  ///   The integer to convert into a BigInteger object
  /// @
  bigIntFromInt: function(integer)
  {
    var bigInt = null;

    if (typeof integer === "number") {
      bigInt = new BigInteger(null);
      bigInt.fromInt(integer);
    }

    return bigInt;
  },

  /// Converts the binary data in BigInteger into a char string.
  bigInt2ByteString: function(bigInteger)
  {
    var result = null;
    if (bigInteger instanceof BigInteger) {
      result = openpgp.util.bin2str(bigInteger.toByteArray());
    }

    return result;
  },

  /// bytes to hex
  bytes2hex: function(bytes)
  {
    return openpgp.util.hexstrdump(bytes);
  },

  /// hex to bytes
  hex2bytes: function(string)
  {
    return openpgp.util.hex2bin(string);
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

  /// Generate a prime number with n bits using the rsa.generate()
  /// in lack of a real generatePrime() method.
  generatePrimeNumber: function(primeBitLength)
  {
    /// rsa.generate() requires a public exponent.
    /// This exponent has to be 3 or 65537 written in base 16.
    ///
    /// 3 => "3"
    /// 65537 => "10001"
    var public_exponent = "10001";

    var rsa = new openpgp.crypto.publicKey.rsa();
    return rsa
      .generate(primeBitLength, public_exponent)
      .then(function(key) {
        return key.q;
      })
      .catch(function(error) {
        console.log(error);
        throw new Error("Something went wrong during prime number generation. Please retry.");
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

  /// TODO
  hashMessage: function(message)
  {
    return openpgp.crypto.hash.sha512(message);
  },

  /// TODO
  isBigInteger: function(bigInteger)
  {
    return (bigInteger instanceof BigInteger);
  },

  /// TODO
  isMPIWithData: function(mpi)
  {
    return (mpi instanceof openpgp.MPI) && (mpi.data instanceof BigInteger);
  },

  /// Validates if the input parameter is a string.
  isString: function(string)
  {
    return (typeof string === "string");
  },

  /// Validates if the input parameter is probably a prime MPI.
  isMPIProbablyPrime: function(mpi)
  {
    return mpi
      && (mpi instanceof openpgp.MPI)
      && (mpi.toBigInteger().isProbablePrime());
  },

  // TODO
  isOpenPGPKey: function(key)
  {
    return (key instanceof openpgp.key.Key);
  },

  /// Checks if the given input is the result of a successful key read operation.
  isKeyReadSuccessful: function(key)
  {
    return key
      && !key.hasOwnProperty("err")
      && key.hasOwnProperty("keys");
  },

  /// TODO
  str2MPI: function(string)
  {
    if (!this.isString(string)) { return null; }

    var mpi = new openpgp.MPI();
    mpi.fromBytes(string);

    return mpi;
  }
};
