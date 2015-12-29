"use strict";

import { assert } from "chai"

import * as client from "../src/client"
import * as util from "../src/util"
import BlindingInformation from "../src/types/blinding_information"

import { controls } from "./helper/client_control"

describe("blinding_information", function() {

  //
  // suite functions
  //

  let blinding_information = null;

  beforeEach( () => {
    blinding_information = new BlindingInformation(null);
  });

  afterEach( () => {
    blinding_information = null;
  });

  //
  // test cases
  //

  describe("#containsPublicBlindingInformation", () => {

    it ("should return false after initialization", () => {
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return false if public exponent is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return false if modulus is missing", () => {
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(blinding_information.containsPublicBlindingInformation());
    });
  });

  describe("#containsAllBlindingInformation", () => {

    it ("should return false after initialization", () => {
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return false if blinding factor is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return false if hashed token is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(blinding_information.containsAllBlindingInformation());
    });
  });

  describe("#fromKey", () => {

    const tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: "string"}, {arg: 123}, {arg: {}}
    ];

    tests.forEach((test) => {
      it ("should return null if input is a " + typeof test.arg, () => {
        assert.isNull(BlindingInformation.fromKey(test.arg));
      });
    });

    it ("should return 'true' if input is a openpgp.key.Key", () => {
      controls.loadFixture("test/fixture/keys_2048bit.html");

      const key = client.getServerPublicKey();
      let blinding_information = BlindingInformation.fromKey(key);
      assert.isNotNull(blinding_information);
      assert.isTrue(blinding_information.containsPublicBlindingInformation());
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
        assert.equal(test.expected, BlindingInformation.isValidFullBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", () => {
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return false if blinding factor is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return false if hashed token is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return true if all necessary information are present", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(BlindingInformation.isValidFullBlindingInformation(blinding_information));
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
        assert.equal(test.expected, BlindingInformation.isValidPublicBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", () => {
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return false if public exponent is missing", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return false if modulus is missing", () => {
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return true if all necessary information are present", () => {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });
  });
});