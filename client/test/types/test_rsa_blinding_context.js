"use strict";

import { assert } from "chai"
import * as client from "../../src/client"
import * as util from "../../src/util"
import RSABlindingContext from "../../src/types/rsa_blinding_context"

import { controls } from "./../helper/client_control"

describe("rsa_blinding_context", function() {

  //
  // suite functions
  //

  let context = null;

  beforeEach( () => {
    context = new RSABlindingContext(null);
  });

  afterEach( () => {
    context = null;
  });

  //
  // test cases
  //

  describe("#containsPublicBlindingInformation", () => {

    it ("should return false after initialization", () => {
      assert.isFalse(context.containsPublicBlindingInformation());
    });

    it ("should return false if public exponent is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      assert.isFalse(context.containsPublicBlindingInformation());
    });

    it ("should return false if modulus is missing", () => {
      context.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(context.containsPublicBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(context.containsPublicBlindingInformation());
    });
  });

  describe("#containsAllBlindingInformation", () => {

    it ("should return false after initialization", () => {
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if blinding factor is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if hashed token is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(context.containsAllBlindingInformation());
    });
  });

  describe("#fromKey", () => {

    const tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: "string"}, {arg: 123}, {arg: {}}
    ];

    tests.forEach((test) => {
      it ("should return null if input is a " + typeof test.arg, () => {
        assert.isNull(RSABlindingContext.fromKey(test.arg));
      });
    });

    it ("should return 'true' if input is a kbpgp {KeyManager}", async (done) => {
      controls.loadFixture("test/fixture/keys_2048bit.html");

      const key = await client.getServerPublicKey();
      let context = RSABlindingContext.fromKey(key);
      assert.isNotNull(context);
      assert.isTrue(context.containsPublicBlindingInformation());

      done();
    });
  });

  describe("#isValidFullBlindingInformation", () => {

    const tests = [
      {arg: null,      expected: false},
      {arg: undefined, expected: false},
      {arg: true,      expected: false},
      {arg: "string",  expected: false},
      {arg: 123, expected: false},
      {arg: {},  expected: false}
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' if input is a " + typeof test.arg, () => {
        assert.equal(test.expected, RSABlindingContext.isValidFullBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", () => {
      assert.isFalse(RSABlindingContext.isValidFullBlindingInformation(context));
    });

    it ("should return false if blinding factor is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(RSABlindingContext.isValidFullBlindingInformation(context));
    });

    it ("should return false if hashed token is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(RSABlindingContext.isValidFullBlindingInformation(context));
    });

    it ("should return true if all necessary information are present", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(RSABlindingContext.isValidFullBlindingInformation(context));
    });
  });

  describe("#isValidPublicBlindingInformation", () => {

    const tests = [
      {arg: null,      expected: false},
      {arg: undefined, expected: false},
      {arg: true,      expected: false},
      {arg: "string",  expected: false},
      {arg: 123, expected: false},
      {arg: {},  expected: false}
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' if input is a " + typeof test.arg, () => {
        assert.equal(test.expected, RSABlindingContext.isValidPublicBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", () => {
      assert.isFalse(RSABlindingContext.isValidPublicBlindingInformation(context));
    });

    it ("should return false if public exponent is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      assert.isFalse(RSABlindingContext.isValidPublicBlindingInformation(context));
    });

    it ("should return false if modulus is missing", () => {
      context.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(RSABlindingContext.isValidPublicBlindingInformation(context));
    });

    it ("should return true if all necessary information are present", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(RSABlindingContext.isValidPublicBlindingInformation(context));
    });
  });
});