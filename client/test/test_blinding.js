"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"

import * as blinding from "../src/blinding"
import * as client from "../src/client"
import * as util from "../src/util"
import BlindingInformation from "../src/types/blinding_information"

import { controls } from "./helper/client_control"

describe("blinding", function() {

  //
  // suite functions
  //

  beforeEach(() => { controls.loadFixture("test/fixture/keys_2048bit.html"); });

  afterEach(() => {});

  //
  // test cases
  //

  describe("#blind_message()", () => {

    let tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: 123}, {arg: {}}, {arg: "123"}
    ];

    tests.forEach((test) => {
      it ("should return 'null' if message is a " + typeof test.arg, () => {
        assert.isNull(blinding.blind_message(test.arg, new BlindingInformation()));
      });
    });

    it ("should return 'null' if not all blinding information are available", () => {
      assert.isNull(blinding.blind_message(util.BigInteger.ZERO, new BlindingInformation()));
    });

    it ("should return a blinded 'BigInteger' with correct input", () => {
      const key = client.getPublicKey();
      let blinding_information = BlindingInformation.fromKey(key);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);

      const blinded_message = blinding.blind_message(util.BigInteger.ONE, blinding_information);
      assert.isTrue(util.isBigInteger(blinded_message));
    });

    tests = [
      { args: {message: "0", blinding_factor:  "3", modulus: "5",  public_exponent: "3"}, expected: "0" },
      { args: {message: "1", blinding_factor:  "5", modulus: "7",  public_exponent: "3"}, expected: "6" },
      { args: {message: "2", blinding_factor:  "7", modulus: "11", public_exponent: "3"}, expected: "4" },
      { args: {message: "3", blinding_factor: "11", modulus: "13", public_exponent: "3"}, expected: "15" },
      { args: {message: "4", blinding_factor: "13", modulus: "17", public_exponent: "3"}, expected: "16" },
      { args: {message: "5", blinding_factor: "17", modulus: "23", public_exponent: "3"}, expected: "70" }
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' for specified input", () => {

        let blinding_information = new BlindingInformation();
        blinding_information.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        blinding_information.modulus = new util.BigInteger(test.args.modulus, 10);
        blinding_information.public_exponent = new util.BigInteger(test.args.public_exponent, 10);
        blinding_information.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.message, 10);
        assert.equal(test.expected, blinding.blind_message(message, blinding_information).toString());
      });
    });
  });

  describe("#unblind_message()", () => {

    let tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: 123}, {arg: {}}, {arg: "R2D2"}
    ];

    tests.forEach((test) => {
      it ("should return 'null' if message is " + test.arg + " (" + typeof test.arg + ")", () => {
        assert.isNull(blinding.unblind_message(test.arg, new BlindingInformation()));
      });
    });

    it ("should return 'null' if not all blinding information are available", () => {
      assert.isNull(blinding.unblind_message(util.BigInteger.ONE, new BlindingInformation()));
    });

    it ("should return an unblinded 'BigInteger' with correct input", () => {
      const key = client.getPublicKey();
      let blinding_information = BlindingInformation.fromKey(key);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);

      const unblinded_message = blinding.unblind_message(util.BigInteger.ZERO, blinding_information);
      assert.isTrue(util.isBigInteger(unblinded_message));
    });

    tests = [
      { args: {blinded_message: "0", blinding_factor:  "3",  modulus: "5"  }, expected: "0" },
      { args: {blinded_message: "1", blinding_factor:  "5",  modulus: "7"  }, expected: "3" },
      { args: {blinded_message: "2", blinding_factor:  "7",  modulus: "11" }, expected: "5" },
      { args: {blinded_message: "3", blinding_factor: "11",  modulus: "13" }, expected: "5" },
      { args: {blinded_message: "4", blinding_factor: "13",  modulus: "17" }, expected: "16"},
      { args: {blinded_message: "5", blinding_factor: "17",  modulus: "23" }, expected: "3" }
    ];

    tests.forEach((test) => {
      it ("should return '" + test.expected + "' for sepcified input", () => {

        let blinding_information = new BlindingInformation();
        blinding_information.blinding_factor = new util.BigInteger(test.args.blinding_factor, 10);
        blinding_information.modulus = new util.BigInteger(test.args.modulus, 10);
        blinding_information.public_exponent = new util.BigInteger("3", 10);
        blinding_information.hashed_token = new util.BigInteger("3", 10);

        const message = new util.BigInteger(test.args.blinded_message, 10);
        const unblinded_message = blinding.unblind_message(message, blinding_information);
        assert.equal(test.expected, unblinded_message.toString(10));
      });
    });
  });

});