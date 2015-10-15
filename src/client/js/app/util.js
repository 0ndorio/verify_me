define(function(require) {

   'use strict';

   var openpgp = require('openpgp');

   /// Converts the binary data in BigInteger into a char string.
   function bigInt2str(bigInteger)
   {
      return openpgp.util.bin2str(bigInteger.toByteArray());
   }
   
   /// bytes to hex
   function bytes2hex(bytes)
   {
      return openpgp.util.hexstrdump(bytes);
   }

   /// hex to bytes
   function hex2bytes(string)
   {
      return openpgp.util.hex2bin(string);
   }

   /// Converts a given armored key string into a openpgp key object.
   ///
   /// @param {string} key_as_string
   ///      The armored key.
   /// @return
   ///      {object} containing the keys represented by the armored key or
   ///      {null} if sth. went wrong during conversion.
   function generateKeyFromString(key_as_string)
   {
      if (!isString(key_as_string)) { return null; }

      var key = openpgp.key.readArmored(key_as_string);
      if (!isKeyReadSuccessful(key)) {
         key = null;
      }

      return key;
   }

   /// Generate a prime number with n bits using the rsa.generate()
   /// in lack of a real generatePrime() method.
   function generatePrimeNumber(primeBitLength)
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
   }

   /// Loads content from textarea with specific id.
   ///
   /// @param {string} text_area_name
   ///      id of the requested text area
   /// @return
   ///      {string} if text area id is valid,
   ///      else {null}
   function getTextAreaContent(text_area_name)
   {
      if (!isString(text_area_name)) { return null; }

      var textarea = document.getElementById(text_area_name);

      var content = null;
      if (textarea !== null) {
         content = textarea.value;
      }

      return content;
   }

   /// TODO
   function hashMessage(message)
   {
      return openpgp.crypto.hash.sha512(message);
   }

   /// Validates if the input parameter is a string.
   function isString(string)
   {
      return (typeof string === "string");
   }

   /// Validates if the input parameter is probably a prime MPI.
   function isMPIProbablyPrime(mpi)
   {
      return mpi
            && (mpi instanceof openpgp.MPI)
            && (mpi.toBigInteger().isProbablePrime());
   }

   /// Checks if the given input is the result of a successful key read operation.
   function isKeyReadSuccessful(key)
   {
      return key
            && !key.hasOwnProperty("err")
            && key.hasOwnProperty("keys");
   }

   /// TODO
   function str2MPI(string)
   {
      if (!isString(string)) { return null; }

      var mpi = new openpgp.MPI();
      mpi.fromBytes(string);

      return mpi;
   }

   return {

      bigInt2str: bigInt2str,
      bytes2hex: bytes2hex,
      hex2bytes: hex2bytes,

      generateKeyFromString:  generateKeyFromString,
      generatePrimeNumber:    generatePrimeNumber,
      getTextAreaContent:     getTextAreaContent,

      hashMessage:   hashMessage,

      isKeyReadSuccessful:    isKeyReadSuccessful,
      isMPIProbablyPrime:     isMPIProbablyPrime,
      isString:               isString,

      str2MPI:    str2MPI
   };
});
