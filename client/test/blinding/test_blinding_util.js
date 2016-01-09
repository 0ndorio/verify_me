"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import blinding_util from "../../src/blinding/blinding_util"
import EcdsaBlinder from "../../src/blinding/ecdsa/blinder_ecdsa"
import EcdsaBlindingContext from "../../src/blinding/ecdsa/blinding_context_ecdsa"
import RsaBlinder from "../../src/blinding/rsa/blinder_rsa"
import RsaBlindingContext from "../../src/blinding/rsa/blinding_context_rsa"

import * as util from "../../src/util"

import sample_keys from "../helper/keys"

describe("blinding_util", function() {

  //
  // suite functions
  //

  before(() => {});

  beforeEach(async () => {
    this.rsa_key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
    this.ecc_key_manager = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
    this.token = new util.BigInteger("3", 16);
  });

  afterEach(() => {
  });

  ///---------------------------------
  /// #createBlinderForKeyManager()
  ///---------------------------------

  describe("#createBlinderForKeyManager()", () => {

    it("should return a rejected promise if input is no {KeyManager} object", async () => {
      return blinding_util.createBlinderForKeyManager(123, this.token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a rejected promise if key algorithm is encryption only key", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      key.primary.key.type = kbpgp.const.openpgp.public_key_algorithms.RSA_ENCRYPT_ONLY;

      return blinding_util.createBlinderForKeyManager(key, this.token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a rejected promise if key algorithm is unknown", async () => {
      this.rsa_key_manager.primary.key.type = -1;
      return blinding_util.createBlinderForKeyManager(this.rsa_key_manager, this.token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a RsaBlinder if input is a rsa key", async () => {
      return blinding_util.createBlinderForKeyManager(this.rsa_key_manager, this.token)
        .then(blinder => assert.instanceOf(blinder, RsaBlinder));
    });

    it("should return an EcdsaBlinder if input is a ecc key", async () => {
      return blinding_util.createBlinderForKeyManager(this.ecc_key_manager, this.token)
        .then(blinder => assert.instanceOf(blinder, EcdsaBlinder));
    });
  });
});