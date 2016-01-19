"use strict";

import { assert } from "chai"
import { BigInteger, Buffer, check, util } from "verifyme_utility"

import EcdsaBlindingContext from "../../../src/blinding/ecdsa/blinding_context_ecdsa"

import sample_keys from "./../../helper/keys"

describe("blinding_context_ecdsa", function() {

  //
  // suite functions
  //

  /** @type {EcdsaBlindingContext} **/
  let context = null;
  /** @type {KeyManager} **/
  let key_manager = null;

  before(async () => {
    key_manager = await util.generateKeyFromString(sample_keys.ecc.bp[256].pub);
  });

  beforeEach( () => {
    context = EcdsaBlindingContext.fromKey(key_manager);
    context.hashed_token = BigInteger.ONE;
    context.blinding_factor.a = BigInteger.ONE;
    context.blinding_factor.b = BigInteger.ONE;
    context.blinding_factor.c = BigInteger.ONE;
    context.blinding_factor.d = BigInteger.ONE;
  });

  afterEach( () => {
    context = null;
  });

  ///-----------------------------------
  /// #isValidBlindingContext()
  ///-----------------------------------

  describe("#isValidBlindingContext", () => {

    it ("should return false after creation", () => {
      context = new EcdsaBlindingContext();
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the curve is missing", () => {
      context.curve = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the hashed token is missing", () => {
      context.hashed_token = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the blinding factor a is missing", () => {
      context.blinding_factor.a = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the blinding factor b is missing", () => {
      context.blinding_factor.b = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the blinding factor c is missing", () => {
      context.blinding_factor.c = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return false if the blinding factor d is missing", () => {
      context.blinding_factor.d = null;
      assert.isFalse(EcdsaBlindingContext.isValidBlindingContext(context));
    });

    it ("should return true if all necessary information are present", () => {
      assert.isTrue(EcdsaBlindingContext.isValidBlindingContext(context));
    });
  });

  ///-----------------------------------
  /// #fromKey()
  ///-----------------------------------

  describe("#fromKey", () => {

    it ("should throw if input is not a {KeyManager}", () => {
      assert.throws(() => EcdsaBlindingContext.fromKey(null));
    });

    it ("should throw if input is not a valid ECDSA {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      assert.throws(() => EcdsaBlindingContext.fromKey(key_manager));
    });

    it ("should return a context object if input is a valid ECDSA {KeyManager}", () => {
      const context = EcdsaBlindingContext.fromKey(key_manager);
      assert.instanceOf(context, EcdsaBlindingContext);
    });
  });

  ///-----------------------------------
  /// #containsAllBlindingInformation()
  ///-----------------------------------

  describe("#containsAllBlindingInformation", () => {

    it ("should return false after creation", () => {
      context = new EcdsaBlindingContext();
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the curve is missing", () => {
      context.curve = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the hashed token is missing", () => {
      context.hashed_token = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the blinding factor a is missing", () => {
      context.blinding_factor.a = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the blinding factor b is missing", () => {
      context.blinding_factor.b = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the blinding factor c is missing", () => {
      context.blinding_factor.c = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return false if the blinding factor d is missing", () => {
      context.blinding_factor.d = null;
      assert.isFalse(context.containsAllBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      assert.isTrue(context.containsAllBlindingInformation());
    });
  });

  ///-----------------------------------
  /// #encodeSignaturePayload()
  ///-----------------------------------

  describe("#encodeSignaturePayload", () => {

    it ("should throw if input data is no {Buffer}", () => {
      assert.throws(() => context(null));
    });

    it ("should return the given Buffer as {BigInteger}", () => {
      const buffer = new Buffer([1, 2, 3]);
      const result = context.encodeSignaturePayload(buffer);

      assert.isTrue(check.isBigInteger(result));
      assert.isTrue(buffer.equals(result.toBuffer()));
    });
  });
});