"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import blinding_util from "../../src/blinding/blinding_util"
import EcdsaBlinder from "../../src/blinding/ecdsa/blinder_ecdsa"
import EcdsaBlindingContext from "../../src/blinding/ecdsa/blinding_context_ecdsa"
import RsaBlinder from "../../src/blinding/rsa/blinder_rsa"
import RsaBlindingContext from "../../src/blinding/rsa/blinding_context_rsa"

import util from "verifyme_utility"

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
    token = new util.BigInteger("3", 16);
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
      rsa_key_manager.primary.key.type = util.public_key_algorithms_tags.RSA_ENCRYPT_ONLY;

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

    it("should return an EcdsaBlinder if input is a ecc key", async (done) => {
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token);

      assert.instanceOf(blinder, EcdsaBlinder);
      done();
    });
  });
});