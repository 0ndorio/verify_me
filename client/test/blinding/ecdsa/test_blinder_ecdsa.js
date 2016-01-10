"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import EcdsaBlinder from "../../../src/blinding/ecdsa/blinder_ecdsa"
import EcdsaBlindingContext from "../../../src/blinding/ecdsa/blinding_context_ecdsa"
import util from "../../../src/util"

import sample_keys from "../../helper/keys"

describe("EcdsaBlinder", function() {

  //
  // suite functions
  //

  before(async () => {
    this.key_manager = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
  });

  beforeEach(async () => {
    let context = new EcdsaBlindingContext();

    this.blinder = new EcdsaBlinder(this.key_manager);
    this.blinder.context = context;
  });

  afterEach(() => {});

  ///---------------------------------
  /// #blind()
  ///---------------------------------

  describe("#blind()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for specified input");

  });

  ///---------------------------------
  /// #initContext()
  ///---------------------------------

  describe("#initContext()", () => {

    it ("should ...");

  });

  ///---------------------------------
  /// #unblind_message_ecdsa()
  ///---------------------------------

  describe("#unblind()", () => {

    it ("should throw an assertion if message is no {BigInteger}");

    it ("should throw an assertion if the blinding context is incomplete");

    it ("should return ... for specified input");

  });
});