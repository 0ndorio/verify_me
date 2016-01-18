"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import EcdsaBlinder from "../../../src/blinding/ecdsa/blinder_ecdsa"
import EcdsaBlindingContext from "../../../src/blinding/ecdsa/blinding_context_ecdsa"
import { check } from "verifyme_utility"

import sample_keys from "../../helper/keys"

describe("EcdsaBlinder", function() {

  //
  // suite functions
  //

  /** @type{EcdsaBlinder} **/
  let blinder = null;

  /** @type{KeyManager} **/
  let key_manager = null;

  before(async () => {
    key_manager = await check.generateKeyFromString(sample_keys.ecc.nist[256].pub);
  });

  beforeEach(async () => {
    let context = EcdsaBlindingContext.fromKey(key_manager);

    blinder = new EcdsaBlinder();
    blinder.context = context;
  });

  afterEach(() => {});

  ///---------------------------------
  /// #initContext()
  ///---------------------------------

  describe("#initContext()", () => {

    it ("should return a rejected promise if the input {KeyManager} is missing", () => {
      return blinder.initContext(null, check.BigInteger.ONE)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should throw if the input {KeyManager} does not contain an ECDSA key", async () => {
      const key_manager = await check.generateKeyFromString(sample_keys.rsa[1024].pub);
      return blinder.initContext(key_manager, check.BigInteger.ONE)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should throw if the the hashed token is no {BigInteger}", () => {
      blinder.initContext(key_manager, 123)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should set the blinder in full prepared state", async () => {
      await blinder.initContext(key_manager, check.BigInteger.ONE);

      assert.isTrue(EcdsaBlindingContext.isValidBlindingContext(blinder.context));
      assert.isTrue(check.isBigInteger(blinder.token));
      assert.isTrue(check.isKeyManagerForEcdsaSign(blinder.key_manager));
    });
  });

  ///---------------------------------
  /// #blind()
  ///---------------------------------

  describe("#blind()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for specified input");

  });

  ///---------------------------------
  /// #unblind_message_ecdsa()
  ///---------------------------------

  describe("#unblind()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for specified input");

  });

  ///---------------------------------
  /// #forgeSignature()
  ///---------------------------------

  describe("#forgeSignature()", () => {

    it ("should ...");
  });
});