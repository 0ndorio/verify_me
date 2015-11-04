"use strict";

var assert = require("chai").assert;
var BlindingInformation = require("../src/types/blinding_information");
var client = require("../src/client");
var controls = require("./helper/helper").controls;
var openpgp = require("openpgp");
var util = require("../src/util");

describe("client", function() {

  //
  // suite functions
  //

  beforeEach(function() {
    controls.loadFixture("test/fixture/keys_1024bit.html");
  });

  afterEach(function() {});

  //
  // test cases
  //

  describe("#getPublicKey()", function() {

    it ("should return users public key as openpgp.Key", function () {
      assert.instanceOf(client.getPublicKey(), openpgp.key.Key);
    });

    it ("must throw if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.throws(function() {client.getPublicKey()}, Error);
    });

    it ("must throw if string is no key representation", function () {
      controls.userPublicKeyString = "123";
      assert.throws(function() {client.getPublicKey()}, Error);
    });
  });

  describe("#getPublicKeyString()", function() {

    it ("should return null if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.isNull(client.getPublicKeyString(), Error);
    });

    var tests = [
      {arg: "a",       expected: "a"},
      {arg: "\u0000",  expected: "\u0000"},
      {arg: "\u0001",  expected: "\u0001"},
      {arg: "\u1232",  expected: "\u1232"},
      {arg: "\n a \n", expected: "a"},
      {arg: "\n",      expected: ""}
    ];

    tests.forEach(function(test) {
      it ("should read '" + test.arg.replace(/\n/g, "\\n") + "' and trim to '" + test.expected + "'", function() {
        controls.userPublicKeyString = test.arg;
        assert.equal(test.expected, client.getPublicKeyString());
      });
    });
  });

  describe("#getToken()", function() {

    it ("should return Token as openpgp.MPI", function () {
      assert.instanceOf(client.getToken(), openpgp.MPI);
    });

    it ("result must pass prime test", function () {
      assert.isTrue(util.isMPIProbablyPrime(client.getToken()));
    });

    it ("must throw if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.throws(function() {client.getToken()}, Error);
    });

    it ("must throw if Token is not prime", function () {
      controls.userTokenString = "A";
      assert.throws(function() {client.getToken()}, Error);
    });
  });

  describe("#getTokenString()", function() {

    it ("should return null if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.isNull(client.getTokenString(), Error);
    });

    var tests = [
      {arg: "a",       expected: "a"},
      {arg: "\u0000",  expected: "\u0000"},
      {arg: "\u0001",  expected: "\u0001"},
      {arg: "\u1232",  expected: "\u1232"},
      {arg: "\n a \n", expected: "a"},
      {arg: "\n",      expected: ""}
    ];

    tests.forEach(function(test) {
      it ("should read '" + test.arg.replace(/\n/g, "\\n") + "' and trim to '" + test.expected + "'", function() {
        controls.userTokenString = test.arg;
        assert.equal(test.expected, client.getTokenString());
      });
    });
  });

  describe("#getServerPublicKey()", function() {

    it ("should return server public key as openpgp.Key", function () {
      assert.instanceOf(client.getServerPublicKey(), openpgp.key.Key);
    });

    it ("must throw if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.throws(function() {client.getServerPublicKey()}, Error);
    });

    it ("must throw if string is no key representation", function () {
      controls.serverPublicKey = "123";
      assert.throws(function() {client.getServerPublicKey()}, Error);
    });
  });

  describe("#getServerPublicKeyString()", function() {

    it ("should return null if id is missing from html", function () {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.isNull(client.getServerPublicKeyString());
    });

    var tests = [
      {arg: "a",       expected: "a"},
      {arg: "\u0000",  expected: ""},
      {arg: "\u0001",  expected: "\u0001"},
      {arg: "\u1232",  expected: "\u1232"},
      {arg: "\n a \n", expected: "a"},
      {arg: "\n",      expected: ""}
    ];

    tests.forEach(function(test) {
      it ("should read '" + test.arg.replace(/\n/g, "\\n") + "' and trim to '" + test.expected + "'", function() {
        controls.serverPublicKey = test.arg;
        assert.equal(test.expected, client.getServerPublicKeyString());
      });
    });
  });

  describe("#collectPublicBlindingInformation()", function() {

    it ("should return an BlindingInformation object", function() {
      assert.isTrue(client.collectPublicBlindingInformation() instanceof BlindingInformation);
    });

    it ("should return an object with modulus and public exponent", function () {
      var blinding_information = client.collectPublicBlindingInformation();
      var isValid = BlindingInformation.isValidPublicBlindingInformation(blinding_information);
      assert.isTrue(isValid);
    });
  });
});