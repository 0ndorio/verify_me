"use strict";

var assert = require("chai").assert;

var client = require("../src/client");
var util = require("../src/util");
var BlindingInformation = require("../src/types/blinding_information");

var controls = require("./helper/helper").controls;

describe("blinding_information", function() {

  //
  // suite functions
  //

  var blinding_information = null;

  beforeEach(function () {
    blinding_information = new BlindingInformation(null);
  });

  afterEach(function () {
    blinding_information = null;
  });

  //
  // test cases
  //

  describe("#containsPublicBlindingInformation", function() {

    it ("should return false after initialization", function() {
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return false if public exponent is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return false if modulus is missing", function() {
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(blinding_information.containsPublicBlindingInformation());
    });

    it ("should return true if all necessary information are present", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(blinding_information.containsPublicBlindingInformation());
    });
  });

  describe("#containsAllBlindingInformation", function() {

    it ("should return false after initialization", function() {
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return false if blinding factor is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return false if hashed token is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(blinding_information.containsAllBlindingInformation());
    });

    it ("should return true if all necessary information are present", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(blinding_information.containsAllBlindingInformation());
    });
  });

  describe("#fromKey", function() {

    var tests = [
      {arg: null,      expected: false},
      {arg: undefined, expected: false},
      {arg: true,      expected: false},
      {arg: "string",  expected: false},
      {arg: 123, expected: false},
      {arg: {},  expected: false}
    ];

    tests.forEach(function(test) {
      it ("should return '" + test.expected + "' if input is a " + typeof test.arg, function() {
        assert.equal(test.expected, blinding_information.fromKey(test.arg));
      });
    });

    it ("should return 'true' if input is a openpgp.key.Key", function() {
      controls.loadFixture("test/fixture/keys_2048bit.html");

      var blinding_information = new BlindingInformation();

      assert.isTrue(blinding_information.fromKey(client.getServerPublicKey()));
      assert.isTrue(blinding_information.containsPublicBlindingInformation());
    });
  });

  describe("#isValidFullBlindingInformation", function() {

    var tests = [
      {arg: null,      expected: false},
      {arg: undefined, expected: false},
      {arg: true,      expected: false},
      {arg: "string",  expected: false},
      {arg: 123, expected: false},
      {arg: {},  expected: false}
    ];

    tests.forEach(function(test) {
      it ("should return '" + test.expected + "' if input is a " + typeof test.arg, function() {
        assert.equal(test.expected, BlindingInformation.isValidFullBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", function() {
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return false if blinding factor is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.hashed_token = new util.BigInteger("3", 10);
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return false if hashed token is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      assert.isFalse(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });

    it ("should return true if all necessary information are present", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      blinding_information.blinding_factor = new util.BigInteger("3", 10);
      blinding_information.hashed_token = new util.BigInteger("4", 10);
      assert.isTrue(BlindingInformation.isValidFullBlindingInformation(blinding_information));
    });
  });

  describe("#isValidPublicBlindingInformation", function() {

    var tests = [
      {arg: null,      expected: false},
      {arg: undefined, expected: false},
      {arg: true,      expected: false},
      {arg: "string",  expected: false},
      {arg: 123, expected: false},
      {arg: {},  expected: false}
    ];

    tests.forEach(function(test) {
      it ("should return '" + test.expected + "' if input is a " + typeof test.arg, function() {
        assert.equal(test.expected, BlindingInformation.isValidPublicBlindingInformation(test.arg));
      });
    });

    it ("should return false after initialization", function() {
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return false if public exponent is missing", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return false if modulus is missing", function() {
      blinding_information.public_exponent = new util.BigInteger("2", 10);
      assert.isFalse(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });

    it ("should return true if all necessary information are present", function() {
      blinding_information.modulus = new util.BigInteger("1", 10);
      blinding_information.public_exponent = new util.BigInteger("2", 10);

      assert.isTrue(BlindingInformation.isValidPublicBlindingInformation(blinding_information));
    });
  });
});