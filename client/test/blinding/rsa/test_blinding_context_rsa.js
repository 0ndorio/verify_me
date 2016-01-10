"use strict";

import { assert } from "chai"

import util from "../../../src/util"
import RSABlindingContext from "../../../src/blinding/rsa/blinding_context_rsa"

import sample_keys from "./../../helper/keys"

describe("blinding_context_rsa", function() {

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

  ///-----------------------------------
  /// #containsAllBlindingInformation()
  ///-----------------------------------

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

  ///-----------------------------------
  /// #fromKey()
  ///-----------------------------------

  describe("#fromKey", () => {

    it ("should throw if input is no {KeyManager}", () => {
      assert.throws(() => RSABlindingContext.fromKey(123), Error);
    });

    it ("should return {RsaBlindingContext} if input is a rsa containing {KeyManager}", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      let context = RSABlindingContext.fromKey(key);

      assert.isNotNull(context);
      assert.isNotNull(context.modulus);
      assert.isNotNull(context.public_exponent);
    });
  });

  ///-----------------------------------
  /// #isValidBlindingContext()
  ///-----------------------------------

  describe("#isValidBlindingContext", () => {

    it ("should return false if input is no {BlindingContext}", () => {
      assert.isFalse(RSABlindingContext.isValidBlindingContext(123));
    });

    it ("should return false after initialization", () => {
      assert.isFalse(RSABlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if Blinding factor is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(RSABlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if hashed token is missing", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(RSABlindingContext.isValidBlindingContext(context));
    });

    it ("should return true if all necessary information are present", () => {
      context.modulus = new util.BigInteger("1", 10);
      context.public_exponent = new util.BigInteger("2", 10);
      context.blinding_factor = new util.BigInteger("3", 10);
      context.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(RSABlindingContext.isValidBlindingContext(context));
    });
  });
});