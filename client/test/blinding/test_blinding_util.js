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

  let rsa_key_manager;
  let ecc_key_manager;
  let token;

  before(() => {});

  beforeEach(async () => {
    rsa_key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
    ecc_key_manager = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
    token = new BigInteger("3", 16);
  });

  afterEach(() => {});

  ///---------------------------------
  /// #createBlinderForKeyManager()
  ///---------------------------------

  describe("#createBlinderForKeyManager()", () => {

    it("should return a rejected promise if input is no {KeyManager} object", (done) => {
      blinding_util.createBlinderForKeyManager(123, token)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should return a rejected promise if key algorithm is encryption only key", (done) => {
      rsa_key_manager.primary.key.type = Tags.public_key_algorithms.RSA_ENCRYPT_ONLY;

      blinding_util.createBlinderForKeyManager(rsa_key_manager, token)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should return a rejected promise if key algorithm is unknown", (done) => {
      rsa_key_manager.primary.key.type = -1;

      blinding_util.createBlinderForKeyManager(rsa_key_manager, token)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should return a RsaBlinder if input is a rsa key", async () => {
      const blinder = await blinding_util.createBlinderForKeyManager(rsa_key_manager, token);
      assert.instanceOf(blinder, RsaBlinder);
    });

    it("should return an ButunEcdsaBlinder if input is a ecc key", async () => {
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token);
      assert.instanceOf(blinder, ButunEcdsaBlinder);
    });

    it("should return an AndreevEcdsaBlinder if input is a ecc key with andreev hint", async () => {
      const hints = { implementation: "andreev" };
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token, hints);

      assert.instanceOf(blinder, AndreevEcdsaBlinder);
    });
  });
});