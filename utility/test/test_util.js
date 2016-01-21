"use strict";

import { assert } from "chai"

import { BigInteger, Buffer } from "../src/types"
import check from "../src/check"
import util from "../src/util"

import { public_keys} from "./helper/keys"

describe("check", function() {

  ///---------------------------------
  /// #generateKeyFromString()
  ///---------------------------------

  describe("#generateKeyFromString", () => {

    it("should throw if input is not a string", () => {
      return util.generateKeyFromString(123)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should throw if input string is not an ascii armored key", () => {
      return util.generateKeyFromString("a broken key")
        .catch(error => assert.instanceOf(error, Error));
    });

    for (const id in public_keys) {
      it("Setting: " + id +" - should return the promise of a {KeyManager} object if input is a pgp key", () => {
        const promise = util.generateKeyFromString(public_keys[id]);
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
      return util.generateTwoPrimeNumbers(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return util.generateTwoPrimeNumbers(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 128", () => {
      return util.generateTwoPrimeNumbers(127)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 128"));
    });

    it("should return a rejected Promise if input bit size is bigger than 8192", () => {
      return util.generateTwoPrimeNumbers(8193)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 8192"));
    });

    it("should return two {BigInteger} prime numbers of given bit length", (done) => {
      const bitLength = 256;

      return util.generateTwoPrimeNumbers(bitLength)
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
      return util.generateRsaBlindingFactor(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return util.generateRsaBlindingFactor(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 256", () => {
      return util.generateRsaBlindingFactor(255)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 256"));
    });

    it("should return a rejected Promise if input bit size is bigger than 16384", () => {
      return util.generateRsaBlindingFactor(16385)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 16384"));
    });

    it("should return a {BigInteger} numbers of given bit length", (done) => {
      const bitLength = 256;

      return util.generateRsaBlindingFactor(bitLength)
        .then((blinding_factor) => {

          assert.isTrue(check.isBigInteger(blinding_factor));
          assert.equal(bitLength, blinding_factor.bitLength());

          done();
        })
    });
  });

  ///---------------------------------
  /// #calculateSha512()
  ///---------------------------------

  describe("#calculateSha512()", () => {

    it("should throw if input parameter is no BigInteger", () => {
      assert.throws(() => util.calculateSha512(123));
    });

    it("should return a hash digest with bit length 512", () => {
      const expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

      const message = BigInteger.fromBuffer(new Buffer("abc"));
      const result = util.calculateSha512(message);

      assert.isTrue(check.isBigInteger(result));
      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });
});
