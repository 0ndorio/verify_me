"use strict";

import { assert } from "chai"
import * as util from "../../src/util"
import ECCBlindingContext from "../../src/types/ecc_blinding_context"

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

  //
  // test cases
  //

  describe("#containsPublicBlindingInformation", () => {

    it ("should return false after initialization");

    it ("should return false if public exponent is missing");

    it ("should return false if modulus is missing");

    it ("should return true if all necessary information are present");
  });

  describe("#containsAllBlindingInformation", () => {

    it ("should return false after initialization");

    it ("should return false if blinding factor is missing");

    it ("should return false if hashed token is missing");

    it ("should return true if all necessary information are present");
  });

  describe("#fromKey", () => {

    it ("should return null if input is not a key");

    it ("should return 'true' if input is a kbpgp {KeyManager}");
  });

  describe("#isValidFullBlindingInformation", () => {

    it ("should return ... if ... ");

    it ("should return false after initialization");

    it ("should return false if blinding factor is missing");

    it ("should return false if hashed token is missing");

    it ("should return true if all necessary information are present");
  });

  describe("#isValidPublicBlindingInformation", () => {

    it ("should return ... if ...");

    it ("should return false after initialization");

    it ("should return false if public exponent is missing");

    it ("should return false if modulus is missing");

    it ("should return true if all necessary information are present");
  });
});