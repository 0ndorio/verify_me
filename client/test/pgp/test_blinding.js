"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import ECClindingContext from "../../src/blinding/blinding_context_ecdsa"
import RSABlindingContext from "../../src/blinding/blinding_context_rsa"

import * as blinding from "../../src/blinding/blinding"
import * as util from "../../src/util"

describe("blinding", function() {

  //
  // suite functions
  //

  beforeEach(() => {});
  afterEach(() => {});

  //
  // test cases
  //
  describe("#blind_message()", () => {
    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinding.blind_message({}, new RSABlindingContext()));
    });

    it ("should throw an assertion if the blinding context is unknown", () => {
      assert.throws(() => blinding.blind_message({}, null));
    });

    it ("should return a correct blinded {BigInteger} with valid RSA input", async (done) => {

      let context = new RSABlindingContext();
      context.blinding_factor = new util.BigInteger("5", 10);
      context.modulus = new util.BigInteger("7", 10);
      context.public_exponent = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("3", 10);

      const blinded_message = blinding.blind_message(util.BigInteger.ONE, context);
      assert.isTrue(util.isBigInteger(blinded_message));
      assert.equal("6", blinded_message.toRadix(10));

      done();
    });

    it ("should return a correct blinded {BigInteger} with valid ECDSA input");

  });

  describe("#blind_ecc_message()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for sepcified input");

  });

  describe("#blind_rsa_message()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinding.blind_message({}, new RSABlindingContext()));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      assert.throws(() => blinding.blind_message(util.BigInteger.ZERO, new RSABlindingContext()));
    });

    const tests = [
      { args: {message: "0", blinding_factor:  "3", modulus: "5" }, expected: "0" },
      { args: {message: "1", blinding_factor:  "5", modulus: "7" }, expected: "6" },
      { args: {message: "2", blinding_factor:  "7", modulus: "11"}, expected: "4" },
      { args: {message: "3", blinding_factor: "11", modulus: "13"}, expected: "15" },
      { args: {message: "4", blinding_factor: "13", modulus: "17"}, expected: "16" },
      { args: {message: "5", blinding_factor: "17", modulus: "23"}, expected: "70" }
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' for specified input", () => {

        let context = new RSABlindingContext();
        context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        context.modulus = new util.BigInteger(test.args.modulus, 10);
        context.public_exponent = new util.BigInteger("3", 10);
        context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.message, 10);
        const blinded_message = blinding.blind_message(message, context);

        assert.isTrue(util.isBigInteger(blinded_message));
        assert.equal(test.expected, blinded_message.toRadix(10));
      });
    });
  });

  describe("#unblind_message()", () => {
    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinding.unblind_message({}, new RSABlindingContext()));
    });

    it ("should throw an assertion if the blinding context is unknown", () => {
      assert.throws(() => blinding.unblind_message({}, null));
    });

    it ("should return a correct unblinded {BigInteger} with valid RSA input", async (done) => {

      let context = new RSABlindingContext();
      context.blinding_factor = new util.BigInteger("5", 10);
      context.modulus = new util.BigInteger("7", 10);
      context.public_exponent = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("3", 10);

      const blinded_message = blinding.unblind_message(util.BigInteger.ONE, context);
      assert.isTrue(util.isBigInteger(blinded_message));
      assert.equal("3", blinded_message.toRadix(10));

      done();
    });

    it ("should return a correct unblinded {BigInteger} with valid ECDSA input");

  });

  describe("#unblind_ecc_message()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for sepcified input");

  });

  describe("#unblind_rsa_message()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinding.unblind_message({}, new RSABlindingContext()));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      assert.throws(() => blinding.unblind_message(util.BigInteger.ONE, new RSABlindingContext()));
    });

    const tests = [
      { args: {blinded_message: "0", blinding_factor:  "3",  modulus: "5"  }, expected: "0" },
      { args: {blinded_message: "1", blinding_factor:  "5",  modulus: "7"  }, expected: "3" },
      { args: {blinded_message: "2", blinding_factor:  "7",  modulus: "11" }, expected: "5" },
      { args: {blinded_message: "3", blinding_factor: "11",  modulus: "13" }, expected: "5" },
      { args: {blinded_message: "4", blinding_factor: "13",  modulus: "17" }, expected: "16"},
      { args: {blinded_message: "5", blinding_factor: "17",  modulus: "23" }, expected: "3" }
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' for sepcified input", () => {

        let context = new RSABlindingContext();
        context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        context.modulus = new util.BigInteger(test.args.modulus, 10);
        context.public_exponent = new util.BigInteger("3", 10);
        context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.blinded_message, 10);
        const unblinded_message = blinding.unblind_message(message, context);

        assert.isTrue(util.isBigInteger(unblinded_message));
        assert.equal(test.expected, unblinded_message.toRadix(10));
      });
    });
  });

});