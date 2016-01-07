"use strict";

import { assert } from "chai"

import * as util from "../../src/util"
import ECCBlindingContext from "../../src/blinding/blinding_context_ecdsa"

import sample_keys from "./../helper/keys"

describe("ecc_blinding_context", function() {

  //
  // suite functions
  //

  let context = null;

  beforeEach( () => {
    context = new ECCBlindingContext(null);
  });

  afterEach( () => {
    context = null;
  });

  ///-----------------------------------
  /// #containsAllBlindingInformation()
  ///-----------------------------------


  describe("#containsAllBlindingInformation", () => {

    it ("should return false after initialization");

    it ("should return false if blinding factor is missing");

    it ("should return false if hashed token is missing");

    it ("should return true if all necessary information are present");
  });

  ///-----------------------------------
  /// #fromKey()
  ///-----------------------------------

  describe("#fromKey", () => {

    it ("should return null if input is not a key");

    it ("should return 'true' if input is a kbpgp {KeyManager}");
  });

  ///-----------------------------------
  /// #isValidBlindingContext()
  ///-----------------------------------

  describe("#isValidBlindingContext", () => {

    it ("should return ... if ... ");

    it ("should return false after initialization");

    it ("should return false if blinding factor is missing");

    it ("should return false if hashed token is missing");

    it ("should return true if all necessary information are present");
  });
});