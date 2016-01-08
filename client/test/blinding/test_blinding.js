"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import Blinding from "../../src/blinding/blinding"
import EcdsaBlindingContext from "../../src/blinding/blinding_context_ecdsa"
import RsaBlindingContext from "../../src/blinding/blinding_context_rsa"
import * as util from "../../src/util"

import sample_keys from "../helper/keys"

describe("Blinding", function() {

  //
  // suite functions
  //

  beforeEach(() => {});
  afterEach(() => {});

  ///---------------------------------
  /// #blind_message()
  ///---------------------------------

  describe("#blind_message()", () => {
    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => Blinding.blind_message({}, new RsaBlindingContext()));
    });

    it ("should throw an assertion if the blinding context is unknown", () => {
      assert.throws(() => Blinding.blind_message({}, null));
    });

    it ("should return a correct blinded {BigInteger} with valid RSA input", async (done) => {

      let context = new RsaBlindingContext();
      context.blinding_factor = new util.BigInteger("5", 10);
      context.modulus = new util.BigInteger("7", 10);
      context.public_exponent = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("3", 10);

      const blinded_message = Blinding.blind_message(util.BigInteger.ONE, context);
      assert.isTrue(util.isBigInteger(blinded_message));
      assert.equal("6", blinded_message.toRadix(10));

      done();
    });

    it ("should return a correct blinded {BigInteger} with valid ECDSA input");

  });

  ///---------------------------------
  /// #blind_message_ecdsa()
  ///---------------------------------

  describe("#blind_message_ecdsa()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for sepcified input");

  });

  ///---------------------------------
  /// #blind_message_rsa()
  ///---------------------------------

  describe("#blind_message_rsa()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => Blinding.blind_message({}, new RsaBlindingContext()));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      assert.throws(() => Blinding.blind_message(util.BigInteger.ZERO, new RsaBlindingContext()));
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

        let context = new RsaBlindingContext();
        context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        context.modulus = new util.BigInteger(test.args.modulus, 10);
        context.public_exponent = new util.BigInteger("3", 10);
        context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.message, 10);
        const blinded_message = Blinding.blind_message(message, context);

        assert.isTrue(util.isBigInteger(blinded_message));
        assert.equal(test.expected, blinded_message.toRadix(10));
      });
    });
  });

  ///---------------------------------
  /// #generateBlindingContext()
  ///---------------------------------

  describe("#generateBlindingContext()", () => {

    const token = new util.BigInteger("3", 16);

    it ("should return a rejected promise if input is no {KeyManager} object", () => {
      return Blinding.generateBlindingContext(123, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return a rejected promise if key algorithm is encryption only key", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      key.primary.key.type = kbpgp.const.openpgp.public_key_algorithms.RSA_ENCRYPT_ONLY;

      return Blinding.generateBlindingContext(key, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return a rejected promise if key algorithm is unknown", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      key.primary.key.type = -1;

      return Blinding.generateBlindingContext(key, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return an RsaBlindingContext if input is a rsa key", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      return Blinding.generateBlindingContext(key, token)
        .then(context => assert.instanceOf(context, RsaBlindingContext));
    });

    it ("should return an EcdsaBlindingContext if input is a ecc key", async () => {
      const key = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
      return Blinding.generateBlindingContext(key, token)
        .then(context => assert.instanceOf(context, EcdsaBlindingContext));
    });
  });

  ///---------------------------------
  /// #unblind_message()
  ///---------------------------------

  describe("#unblind_message()", () => {
    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => Blinding.unblind_message({}, new RsaBlindingContext()));
    });

    it ("should throw an assertion if the blinding context is unknown", () => {
      assert.throws(() => Blinding.unblind_message({}, null));
    });

    it ("should return a correct unblinded {BigInteger} with valid RSA input", async (done) => {

      let context = new RsaBlindingContext();
      context.blinding_factor = new util.BigInteger("5", 10);
      context.modulus = new util.BigInteger("7", 10);
      context.public_exponent = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("3", 10);

      const blinded_message = Blinding.unblind_message(util.BigInteger.ONE, context);
      assert.isTrue(util.isBigInteger(blinded_message));
      assert.equal("3", blinded_message.toRadix(10));

      done();
    });

    it ("should return a correct unblinded {BigInteger} with valid ECDSA input");

  });

  ///---------------------------------
  /// #unblind_message_ecdsa()
  ///---------------------------------

  describe("#unblind_message_ecdsa()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for sepcified input");

  });

  ///---------------------------------
  /// #unblind_message_rsa()
  ///---------------------------------

  describe("#unblind_message_rsa()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => Blinding.unblind_message({}, new RsaBlindingContext()));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      assert.throws(() => Blinding.unblind_message(util.BigInteger.ONE, new RsaBlindingContext()));
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

        let context = new RsaBlindingContext();
        context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        context.modulus = new util.BigInteger(test.args.modulus, 10);
        context.public_exponent = new util.BigInteger("3", 10);
        context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.blinded_message, 10);
        const unblinded_message = Blinding.unblind_message(message, context);

        assert.isTrue(util.isBigInteger(unblinded_message));
        assert.equal(test.expected, unblinded_message.toRadix(10));
      });
    });
  });

});