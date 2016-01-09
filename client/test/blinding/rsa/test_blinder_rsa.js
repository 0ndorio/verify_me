"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import RsaBlinder from "../../../src/blinding/rsa/blinder_rsa"
import RsaBlindingContext from "../../../src/blinding/rsa/blinding_context_rsa"
import * as util from "../../../src/util"

import sample_keys from "../../helper/keys"

describe("RsaBlinder", function() {

  //
  // suite functions
  //

  before(async () => {
    this.key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
  });

  beforeEach(async () => {
    let context = new RsaBlindingContext();
    context.blinding_factor = new util.BigInteger("1", 10);
    context.modulus = new util.BigInteger("1", 10);
    context.public_exponent = new util.BigInteger("1", 10);
    context.hashed_token = new util.BigInteger("1", 10);

    this.blinder = new RsaBlinder(this.key_manager);
    this.blinder.context = context;
  });

  afterEach(() => {});

  ///---------------------------------
  /// #blind()
  ///---------------------------------

  describe("#blind()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => this.blinder.blind({}));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      this.blinder.context = null;
      assert.throws(() => this.blinder.blind(util.BigInteger.ZERO));
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

        this.blinder.context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        this.blinder.context.modulus = new util.BigInteger(test.args.modulus, 10);
        this.blinder.context.public_exponent = new util.BigInteger("3", 10);
        this.blinder.context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.message, 10);
        const blinded_message = this.blinder.blind(message);

        assert.equal(test.expected, blinded_message.toRadix(10));
      });
    }
  });

  ///---------------------------------
  /// #initContext()
  ///---------------------------------

  describe("#initContext()", () => {

    it ("should ...");

  });

  ///---------------------------------
  /// #unblind()
  ///---------------------------------

  describe("#unblind()", () => {

    it ("should throw an assertion if message is no {BigInteger}", () => {
      assert.throws(() => this.blinder.unblind({}));
    });

    it ("should throw an assertion if the blinding context is incomplete", () => {
      this.blinder.context = null;
      assert.throws(() => this.blinder.unblind(util.BigInteger.ONE));
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

        this.blinder.context.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        this.blinder.context.modulus = new util.BigInteger(test.args.modulus, 10);
        this.blinder.context.public_exponent = new util.BigInteger("3", 10);
        this.blinder.context.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.blinded_message, 10);
        const unblinded_message = this.blinder.unblind(message);

        assert.isTrue(util.isBigInteger(unblinded_message));
        assert.equal(test.expected, unblinded_message.toRadix(10));
      });
    }
  });
});