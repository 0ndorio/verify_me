"use strict";

import { assert } from "chai"
import { BigInteger, check, Tags, util } from "verifyme_utility"

import blinding_util from "../../src/blinding/blinding_util"
import AndreevEcdsaBlinder from "../../src/blinding/ecdsa_andreev/blinder"
import ButunEcdsaBlinder from "../../src/blinding/ecdsa_butun/blinder"
import RsaBlinder from "../../src/blinding/rsa/blinder_rsa"

import sample_keys from "../helper/keys"

describe("blinding_util", function() {

  //
  // suite functions
  //

  let rsa_key_manager = null;
  let ecc_key_manager = null;
  let token = null;

  before(() => {
  });

  beforeEach(async () => {
    rsa_key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
    ecc_key_manager = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
    token = new BigInteger("3", 16);
  });

  afterEach(() => {
  });

  ///---------------------------------
  /// #createBlinderForKeyManager()
  ///---------------------------------

  describe("#createBlinderForKeyManager()", () => {

    it("should return a rejected promise if input is no {KeyManager} object", () => {
      return blinding_util.createBlinderForKeyManager(123, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a rejected promise if key algorithm is encryption only key", () => {
      rsa_key_manager.primary.key.type = Tags.public_key_algorithms.RSA_ENCRYPT_ONLY;

      return blinding_util.createBlinderForKeyManager(rsa_key_manager, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a rejected promise if key algorithm is unknown", () => {
      rsa_key_manager.primary.key.type = -1;

      return blinding_util.createBlinderForKeyManager(rsa_key_manager, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a RsaBlinder if input is a rsa key", async (done) => {
      const blinder = await blinding_util.createBlinderForKeyManager(rsa_key_manager, token);

      assert.instanceOf(blinder, RsaBlinder);
      done();
    });

    it("should return an ButunEcdsaBlinder if input is a ecc key", async (done) => {
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token);

      assert.instanceOf(blinder, ButunEcdsaBlinder);
      done();
    });

    it("should return an AndreevEcdsaBlinder if input is a ecc key with andreev hint", async (done) => {

      const hints = { implementation: "andreev" };
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token, hints);

      assert.instanceOf(blinder, AndreevEcdsaBlinder);
      done();
    });
  });
});