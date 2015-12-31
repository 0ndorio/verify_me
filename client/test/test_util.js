"use strict";

import { assert } from "chai"

import * as client from "../src/client"
import * as util from "../src/util"

import { controls } from "./helper/client_control"
import { public_keys } from "./helper/keys"

describe("util", function() {

  describe("#generateKeyFromString", () => {

    it("should return null if input is not a string", () => {
      assert.isNull(util.generateKeyFromString(123));
    });

    it("should return null if input string is not an ascii armored key", () => {
      assert.isNull(util.generateKeyFromString("a broken key"));
    });

    for (const key_string of public_keys) {
      it("should return a {KeyManager} object if input is a valid ascii armored key", () => {
        const key = util.generateKeyFromString(key_string);
        assert.isTrue(util.isKeyManager(key));
      });
    }
  });

  describe("#generateTwoPrimeNumbers", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return util.generateTwoPrimeNumbers(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error, "no integer"));
    });

    it("should throw an error if input bit size is not multiple of 8", () => {
      return util.generateTwoPrimeNumbers(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error, "multiple of 8"));
    });

    it("should throw an error if input bit size is to small", () => {
      return util.generateTwoPrimeNumbers(127)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error, ">= 128"));
    });

    it("should throw an error if input bit size is to big", () => {
      return util.generateTwoPrimeNumbers(8193)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error, "<= 8192"));
    });

    it("should return two {BigInteger} prime numbers of given bit length", (done) => {
      const bitLength = 256;

      return util.generateTwoPrimeNumbers(bitLength)
        .then((primeNumbers) => {

          assert.equal(2, primeNumbers.length);

          primeNumbers.forEach((prime) => {
            assert.isTrue(util.isBigInteger(prime));
            assert.isTrue(prime.isProbablePrime());
            assert.equal(bitLength, prime.bitLength());
          });
          done();
        })
    });
  });

  describe("#generateBlindingFactor", () => {
    it("should ...");
  });

  describe("#hashMessage()", () => {

    it("should return null if input parameter is no string", () => {
      assert.isNull(util.hashMessage(123));
    });

    it("should return a hash digest with bit length 512", () => {
      const expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

      const result = util.hashMessage("abc");
      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });

  describe("#isBigInteger()", () => {

    const tests = [
      {arg: "123"}, {arg: 123}, {arg: true}, {arg: {}}, {arg: []}, {arg: undefined}
    ];

    for (const test of tests) {
      it("should return false when parameter is a not a BigInteger", () => {
        assert.isFalse(util.isBigInteger(test.arg));
      });
    }

    it ("should return true when input parameter is a valid {BigInteger}", () => {
      assert.isTrue(util.isBigInteger(util.BigInteger.ZERO));
    });
  });

  describe("#isInteger()", () => {

    const tests = [
      {arg: "123"}, {arg: 123.45}, {arg: true}, {arg: {}}, {arg: []}, {arg: undefined}
    ];

    for (const test of tests) {
      it ("should return false when input parameter is not a valid integer", () => {
        assert.isFalse(util.isInteger(test.arg));
      });
    }

    it ("should return true when input parameter is a valid integer", () => {
      assert.isTrue(util.isInteger(123));
    });
  });

  describe("#isObject()", () => {

    const false_tests = [
      {arg: undefined}, {arg: 123}, {arg: true}, {arg: "123"}
    ];

    for (const test of false_tests) {
      it("should return false when parameter is not an object", () => {
        assert.isFalse(util.isObject(test.arg));
      });
    }

    const true_tests = [
      {arg: {}}, {arg: []}, {arg: () => {}}, {arg: util.BigInteger.ZERO}
    ];

    for (const test of true_tests) {
      it("should return true when parameter is an object", () => {
        assert.isTrue(util.isObject(test.arg));
      });
    }
  });

  describe("#isKeyManager()", () => {

    const tests = [
      {arg: undefined}, {arg: 123}, {arg: true}, {arg: "123"}, {arg: {}}, {arg: []}
    ];

    for (const test of tests) {
      it("should return false when parameter is not a {KeyManager}", () => {
        assert.isFalse(util.isKeyManager(test.arg));
      });
    }

    it("should return true when parameter is a {KeyManager}", () => {
      const key_manager = util.generateKeyFromString(public_keys[0]);
      assert.isFalse(util.isKeyManager(key_manager));
    });
  });

  describe("#isString()", () => {

    const tests = [
      {arg: undefined}, {arg: 123}, {arg: true}, {arg: {}}, {arg: []}
    ];

    for (const test in tests) {
      it("should return false when parameter is not a string", () => {
        assert.isFalse(util.isString(test.arg));
      });
    }

    it("should return true when parameter is a string", () => {
      assert.isTrue(util.isString("123"));
    });
  });
});
