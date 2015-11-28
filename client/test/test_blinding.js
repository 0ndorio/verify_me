"use strict";

var assert = require("chai").assert;
var blinding = require("../src/blinding");
var BlindingInformation = require("../src/types/blinding_information");
var client = require("../src/client");
var controls = require("./helper/helper").controls;
var util = require("../src/util");

describe("blinding", function() {

  //
  // suite functions
  //

  beforeEach(function() {
    controls.loadFixture("test/fixture/keys_2048bit.html");
  });

  afterEach(function() {});

  //
  // test cases
  //

  describe("#blind_message()", function() {

    var tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: 123}, {arg: {}}
    ];

    tests.forEach(function(test) {
      it ("should return 'null' if message is a " + typeof test.arg, function() {
        assert.isNull(blinding.blind_message(test.arg, new BlindingInformation()));
      });
    });

    it ("should return 'null' if not all blinding information are available", function() {
      assert.isNull(blinding.blind_message("message", new BlindingInformation()));
    });

    it ("should return a blinded 'BigInteger' with correct input", function () {
      var blinding_information = new BlindingInformation();
      blinding_information.fromKey(client.getPublicKey());
      blinding_information.blinding_factor = util.int2BigInt(3);
      blinding_information.hashed_token = util.int2BigInt(3);

      assert.isTrue(util.isBigInteger(blinding.blind_message("bob", blinding_information)));
    });

    var tests = [
      { args: {message: "\u0000", blinding_factor:  3, modulus: 5,  public_exponent: 3}, expected: "0" },
      { args: {message: "\u0001", blinding_factor:  5, modulus: 7,  public_exponent: 3}, expected: "6" },
      { args: {message: "\u0002", blinding_factor:  7, modulus: 11, public_exponent: 3}, expected: "4" },
      { args: {message: "\u0003", blinding_factor: 11, modulus: 13, public_exponent: 3}, expected: "15" },
      { args: {message: "\u0004", blinding_factor: 13, modulus: 17, public_exponent: 3}, expected: "16" },
      { args: {message: "\u0005", blinding_factor: 17, modulus: 23, public_exponent: 3}, expected: "70" }
    ];

    tests.forEach(function(test) {
      it ("should return '" + test.expected + "' for sepcified input", function() {

        var blinding_information = new BlindingInformation();
        blinding_information.blinding_factor = util.int2BigInt(test.args.blinding_factor);
        blinding_information.modulus = util.int2BigInt(test.args.modulus);
        blinding_information.public_exponent = util.int2BigInt(test.args.public_exponent);
        blinding_information.hashed_token = util.int2BigInt(3);

        assert.equal(test.expected, blinding.blind_message(test.args.message, blinding_information).toString());
      });
    });
  });

  describe("#unblind_message()", function() {

    var tests = [
      {arg: null}, {arg: undefined}, {arg: true}, {arg: 123}, {arg: {}}, {arg: "R2D2"}
    ];

    tests.forEach(function(test) {
      it ("should return 'null' if message is " + test.arg + " (" + typeof test.arg + ")", function() {
        assert.isNull(blinding.unblind_message(test.arg, new BlindingInformation()));
      });
    });

    it ("should return 'null' if not all blinding information are available", function() {
      assert.isNull(blinding.unblind_message("message", new BlindingInformation()));
    });

    it ("should return an unblinded 'BigInteger' with correct input", function () {
      var blinding_information = new BlindingInformation();
      blinding_information.fromKey(client.getPublicKey());
      blinding_information.blinding_factor = util.int2BigInt(3);
      blinding_information.hashed_token = util.int2BigInt(3);

      assert.isTrue(util.isBigInteger(blinding.unblind_message("123", blinding_information)));
    });

    var tests = [
      { args: {message: "0", blinding_factor:  3,  modulus: 5  }, expected: "0" },
      { args: {message: "1", blinding_factor:  5,  modulus: 7  }, expected: "3" },
      { args: {message: "2", blinding_factor:  7,  modulus: 11 }, expected: "16" },
      { args: {message: "3", blinding_factor: 11, modulus: 13 }, expected: "18" },
      { args: {message: "4", blinding_factor: 13, modulus: 17 }, expected: "16" },
      { args: {message: "5", blinding_factor: 17, modulus: 23 }, expected: "95" }
    ];

    tests.forEach(function(test) {
      it ("should return '" + test.expected + "' for sepcified input", function() {

        var blinding_information = new BlindingInformation();
        blinding_information.blinding_factor = util.int2BigInt(test.args.blinding_factor);
        blinding_information.modulus = util.int2BigInt(test.args.modulus);
        blinding_information.public_exponent = util.int2BigInt(3);
        blinding_information.hashed_token = util.int2BigInt(3);

        var unblinded_message = blinding.unblind_message(test.args.message, blinding_information);
        assert.equal(test.expected, unblinded_message.toString());
      });
    });
  });

});