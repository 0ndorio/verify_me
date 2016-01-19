"use strict";

import { assert } from "chai"
import { Buffer, ecc } from "kbpgp"

import { BigInteger } from "../src/types"
import check from "../src/check"
import keys, { public_keys} from "./helper/keys"

describe("check", function() {

  ///---------------------------------
  /// #assert()
  ///---------------------------------

  describe("#assert", () => {

    it("nothing should happen when condition validates to true", () => {
      assert(true);
    });

    it("should throw if condition validates to false", () => {
      assert.throws(() => assert(false));
    });

    it("should throw with custom message if condition validates to false", () => {
      const custom_message = "custom message";
      assert.throws(() => assert(false, custom_message), custom_message);
    });
  });

  ///---------------------------------
  /// #generateKeyFromString()
  ///---------------------------------

  describe("#generateKeyFromString", () => {

    it("should throw if input is not a string", () => {
      return check.generateKeyFromString(123)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should throw if input string is not an ascii armored key", () => {
      return check.generateKeyFromString("a broken key")
        .catch(error => assert.instanceOf(error, Error));
    });

    for (const id in public_keys) {
      it("Setting: " + id +" - should return the promise of a {KeyManager} object if input is a pgp key", () => {
        const promise = check.generateKeyFromString(public_keys[id]);
        assert.instanceOf(promise, Promise);

        return promise
          .then(key => assert.isTrue(check.isKeyManager(key)));
      });
    }
  });

  ///---------------------------------
  /// #generateTwoPrimeNumbers()
  ///---------------------------------

  describe("#generateTwoPrimeNumbers", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return check.generateTwoPrimeNumbers(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return check.generateTwoPrimeNumbers(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 128", () => {
      return check.generateTwoPrimeNumbers(127)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 128"));
    });

    it("should return a rejected Promise if input bit size is bigger than 8192", () => {
      return check.generateTwoPrimeNumbers(8193)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 8192"));
    });

    it("should return two {BigInteger} prime numbers of given bit length", (done) => {
      const bitLength = 256;

      return check.generateTwoPrimeNumbers(bitLength)
        .then((primeNumbers) => {

          assert.equal(2, primeNumbers.length);

          primeNumbers.forEach((prime) => {
            assert.isTrue(check.isBigInteger(prime));
            assert.isTrue(prime.isProbablePrime());
            assert.equal(bitLength, prime.bitLength());
          });
          done();
        })
    });
  });

  ///---------------------------------
  /// #generateRsaBlindingFactor()
  ///---------------------------------

  describe("#generateRsaBlindingFactor", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return check.generateRsaBlindingFactor(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return check.generateRsaBlindingFactor(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 256", () => {
      return check.generateRsaBlindingFactor(255)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 256"));
    });

    it("should return a rejected Promise if input bit size is bigger than 16384", () => {
      return check.generateRsaBlindingFactor(16385)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 16384"));
    });

    it("should return a {BigInteger} numbers of given bit length", (done) => {
      const bitLength = 256;

      return check.generateRsaBlindingFactor(bitLength)
        .then((blinding_factor) => {

          assert.isTrue(check.isBigInteger(blinding_factor));
          assert.equal(bitLength, blinding_factor.bitLength());

          done();
        })
    });
  });

  ///---------------------------------
  /// #hashMessageSha512()
  ///---------------------------------

  describe("#hashMessageSha512()", () => {

    it("should throw if input parameter is no string", () => {
      assert.throws(() => check.hashMessageSha512(123));
    });

    it("should return a hash digest with bit length 512", () => {
      const expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

      const result = check.hashMessageSha512("abc");

      assert.isTrue(check.isBigInteger(result));
      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });

  ///---------------------------------
  /// #isBigInteger()
  ///---------------------------------

  describe("#isBigInteger()", () => {

    it("should return false when parameter is a no {BigInteger}", () => {
      assert.isFalse(check.isBigInteger(123));
    });

    it ("should return true when input parameter is a valid {BigInteger}", () => {
      assert.isTrue(check.isBigInteger(BigInteger.ZERO));
    });
  });

  ///---------------------------------
  /// #isBuffer()
  ///---------------------------------

  describe("#isBuffer()", () => {

    it("should return false when parameter is a no {Buffer}", () => {
      assert.isFalse(check.isBuffer(123));
    });

    it ("should return true when input parameter is a valid {Buffer}", () => {
      assert.isTrue(check.isBuffer(new Buffer(123)));
    });
  });

  ///---------------------------------
  /// #isCurve()
  ///---------------------------------

  describe("#isCurve()", () => {

    it("should return false when parameter is a no {Curve}", () => {
      assert.isFalse(check.isCurve(123));
    });

    it ("should return true when input parameter is a valid {Curve}", () => {
      assert.isTrue(check.isCurve(ecc.curves.brainpool_p512()));
    });
  });

  ///---------------------------------
  /// #isFunction()
  ///---------------------------------

  describe("#isFunction()", () => {

    it ("should return false when input parameter is not a valid {function}", () => {
      assert.isFalse(check.isFunction(123));
    });

    it ("should return true when input parameter is a valid {function}", () => {
      assert.isTrue(check.isFunction(() => {}));
    });
  });

  ///---------------------------------
  /// #isInteger()
  ///---------------------------------

  describe("#isInteger()", () => {

    it ("should return false when input parameter is not a valid integer {number}", () => {
      assert.isFalse(check.isInteger("123"));
    });

    it ("should return true when input parameter is a valid integer {number}", () => {
      assert.isTrue(check.isInteger(123));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManager({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await check.generateKeyFromString(public_keys[0]);
      assert.isTrue(check.isKeyManager(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManagerForEcdsaSign()
  ///---------------------------------

  describe("#isKeyManagerForEcdsaSign()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManagerForEcdsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await check.generateKeyFromString(keys.ecc.bp[512].pub);
      assert.isTrue(check.isKeyManagerForEcdsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManagerForRsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await check.generateKeyFromString(keys.rsa[1024].pub);
      assert.isTrue(check.isKeyManagerForRsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isObject()
  ///---------------------------------

  describe("#isObject()", () => {

    it("should return false when parameter is not an {object}", () => {
      assert.isFalse(check.isObject(123));
    });

    it("should return true when parameter is an {object}", () => {
      assert.isTrue(check.isObject({}));
    });
  });

  ///---------------------------------
  /// #isPoint()
  ///---------------------------------

  describe("#isPoint()", () => {

    it("should return false when parameter is not a {Point}", () => {
      assert.isFalse(check.isPoint(123));
    });

    it("should return true when parameter is a {Point}", () => {
      assert.isTrue(check.isPoint(ecc.curves.brainpool_p512().G));
    });
  });

  ///---------------------------------
  /// #isString()
  ///---------------------------------

  describe("#isString()", () => {

    it("should return false when parameter is not a {string}", () => {
      assert.isFalse(check.isString(123));
    });

    it("should return true when parameter is a {string}", () => {
      assert.isTrue(check.isString("123"));
    });
  });
});
