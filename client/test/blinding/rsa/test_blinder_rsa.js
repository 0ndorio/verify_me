"use strict";

import { assert } from "chai"
import { BigInteger, check, util } from "verifyme_utility"

import RsaBlinder from "../../../src/blinding/rsa/blinder_rsa"
import RsaBlindingContext from "../../../src/blinding/rsa/blinding_context_rsa"

import sample_keys from "../../helper/keys"

describe("RsaBlinder", function() {

  //
  // suite functions
  //

  /** @type {RsaBlinder} **/
  let blinder = null;

  /** @type {KeyManager} **/
  let key_manager = null;

  before(async () => {
    key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
  });

  beforeEach(async () => {
    let context = RsaBlindingContext.fromKey(key_manager);
    context.hashed_token = BigInteger.ONE;

    blinder = new RsaBlinder();
    blinder.context = context;
  });

  afterEach(() => {});

  ///---------------------------------
  /// #initContext()
  ///---------------------------------

  describe("#initContext()", () => {

    it ("should throw if the input {KeyManager} is missing", () => {
      return blinder.initContext(null, BigInteger.ONE)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should throw if the input {KeyManager} does not contain an RSA key", async () => {
      const key_manager = await util.generateKeyFromString(sample_keys.ecc.bp[256].pub);
      return blinder.initContext(key_manager, BigInteger.ONE)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should throw if the the hashed token is no {BigInteger}", () => {
      return blinder.initContext(key_manager, 123)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should set the blinder in full prepared state", async () => {
      await blinder.initContext(key_manager, BigInteger.ONE);

      assert.isTrue(RsaBlindingContext.isValidBlindingContext(blinder.context));
      assert.isTrue(check.isBigInteger(blinder.token));
      assert.isTrue(check.isKeyManagerForRsaSign(blinder.key_manager));
    });
  });

  ///---------------------------------
  /// #blind()
  ///---------------------------------

  describe("#blind()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinder.blind({}));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      blinder.context = null;
      assert.throws(() => blinder.blind(BigInteger.ZERO));
    });

    const tests = [
      { args: {message: "0", blinding_factor:  "3", modulus: "5" }, expected: "0" },
      { args: {message: "1", blinding_factor:  "5", modulus: "7" }, expected: "6" },
      { args: {message: "2", blinding_factor:  "7", modulus: "11"}, expected: "4" },
      { args: {message: "3", blinding_factor: "11", modulus: "13"}, expected: "15" },
      { args: {message: "4", blinding_factor: "13", modulus: "17"}, expected: "16" },
      { args: {message: "5", blinding_factor: "17", modulus: "23"}, expected: "70" }
    ];

    for (const test of tests) {
      it("Setting: " + tests.indexOf(test) + " - should return a correct blinded message", () => {

        blinder.context.blinding_factor = new BigInteger(test.args.blinding_factor, 10);
        blinder.context.modulus = new BigInteger(test.args.modulus, 10);
        blinder.context.public_exponent = new BigInteger("3", 10);
        blinder.context.hashed_token = new BigInteger("3", 10);

        const message = new BigInteger(test.args.message, 10);
        const blinded_message = blinder.blind(message);

        assert.equal(test.expected, blinded_message.toRadix(10));
      });
    }
  });

  ///---------------------------------
  /// #unblind()
  ///---------------------------------

  describe("#unblind()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => blinder.unblind({}));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      blinder.context = null;
      assert.throws(() => blinder.unblind(BigInteger.ONE));
    });

    const tests = [
      { args: {blinded_message: "0", blinding_factor:  "3",  modulus: "5"  }, expected: "0" },
      { args: {blinded_message: "1", blinding_factor:  "5",  modulus: "7"  }, expected: "3" },
      { args: {blinded_message: "2", blinding_factor:  "7",  modulus: "11" }, expected: "5" },
      { args: {blinded_message: "3", blinding_factor: "11",  modulus: "13" }, expected: "5" },
      { args: {blinded_message: "4", blinding_factor: "13",  modulus: "17" }, expected: "16"},
      { args: {blinded_message: "5", blinding_factor: "17",  modulus: "23" }, expected: "3" }
    ];

    for (const test of tests) {
      it ("Setting: " + tests.indexOf(test) + " - should return a correct unblinded message", () => {

        blinder.context.blinding_factor = new BigInteger(test.args.blinding_factor, 10);
        blinder.context.modulus = new BigInteger(test.args.modulus, 10);
        blinder.context.public_exponent = new BigInteger("3", 10);
        blinder.context.hashed_token = new BigInteger("3", 10);

        const message = new BigInteger(test.args.blinded_message, 10);
        const unblinded_message = blinder.unblind(message);

        assert.isTrue(check.isBigInteger(unblinded_message));
        assert.equal(test.expected, unblinded_message.toRadix(10));
      });
    }
  });

  ///---------------------------------
  /// #forgeSignature()
  ///---------------------------------

  describe("#forgeSignature()", () => {

    it ("should ...");
  });
});