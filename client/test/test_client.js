"use strict";

var assert = require("chai").assert;
var BlindingInformation = require("../src/types/blinding_information");
var client = require("../src/client");
var controls = require("./helper/helper").controls;
var kbpgp = require("kbpgp");
var sinon = require('sinon');
var util = require("../src/util");

describe("client", function() {

  //
  // suite functions
  //

  beforeEach(function() {
    controls.loadFixture("test/fixture/keys_2048bit.html");

    this.server = sinon.fakeServer.create();
    this.server.autoRespond = true;
  });

  afterEach(function() {
    this.server.restore();
  });

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

  describe("#sendBlindingRequest()", function() {

    it("should return a promise", function() {
      assert.instanceOf(client.sendBlindingRequest(), Promise);
    });

    it("should reject with wrong typed input for blinded_message", function() {

      return client.sendBlindingRequest(123)
        .then(function() { assert.fail(); })
        .catch(function(error) {
          assert.typeOf(error, 'string');
        });
    });

    it("should reject with wrong typed input for blinding_information", function(done) {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = 123;

      return client.sendBlindingRequest("1234", blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.typeOf(error, 'string');
          done();
        });
    });

    it("should reject when a network error occures", function(done) {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      var request_promise = client.sendBlindingRequest("1234", blinding_information)
        .then(function (answer) { done("Should not happend: " + answer); })
        .catch(function(error) {
          assert.instanceOf(error, Error);
          done();
        });

      assert.equal(1, this.server.requests.length);
      this.server.requests[0].onload = null;
      this.server.requests[0].abort();

      return request_promise;
    });

    it("should reject and return status text error if status is not 200", function(done) {

      var expected = { code: 404, status_text: new Error("Not Found") };
      this.server.respondWith([expected.code, { "Content-Type": "text/plain" }, ""]);

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      return client.sendBlindingRequest("" , blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.instanceOf(error, Error);
          done();
        });
    });

    it("should resolve and return server response if status is 200", function() {

      var expected = "My expected response";
      this.server.respondWith([200, { "Content-Type": "text/plain" }, expected]);

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      return client.sendBlindingRequest("" , blinding_information)
        .then(function(answer) {
          assert.equal(expected, answer);
        });
    });
  });
});