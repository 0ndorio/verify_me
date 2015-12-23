"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"
import * as sinon from "sinon"

import * as client from "../src/client"
import * as util from "../src/util"
import BlindingInformation from "../src/types/blinding_information"

import { controls } from "./helper/helper"

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

    it ("should return users public key as kbpgp.Key", function () {
      assert.instanceOf(client.getPublicKey(), kbpgp.KeyManager);
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

    const tests = [
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

    it ("should return Token as BigInteger", function () {
      const token = client.getToken();
      assert.isTrue(util.isBigInteger(token));
    });

    it ("result must pass prime test", function () {
      const token = client.getToken();
      assert.isTrue(token.isProbablePrime());
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

    const tests = [
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

    it ("should return server public key as kbpgp.Key", function () {
      assert.instanceOf(client.getServerPublicKey(), kbpgp.KeyManager);
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

    const tests = [
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
      const blinding_information = client.collectPublicBlindingInformation();
      const isValid = BlindingInformation.isValidPublicBlindingInformation(blinding_information);
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

      const blinding_information = new BlindingInformation();
      blinding_information.hashed_token = 123;

      return client.sendBlindingRequest("1234", blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.typeOf(error, 'string');
          done();
        });
    });

    it("should reject when a network error occures", function(done) {

      const blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2BigInt("\u0000");

      const request_promise = client.sendBlindingRequest("1234", blinding_information)
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

      const expected = { code: 404, status_text: new Error("Not Found") };
      this.server.respondWith([expected.code, { "Content-Type": "text/plain" }, ""]);

      let blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2BigInt("\u0000");

      return client.sendBlindingRequest("" , blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.instanceOf(error, Error);
          done();
        });
    });

    it("should resolve and return server response if status is 200", function() {

      const expected = "My expected response";
      this.server.respondWith([200, { "Content-Type": "text/plain" }, expected]);

      let blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2BigInt("\u0000");

      return client.sendBlindingRequest("" , blinding_information)
        .then(function(answer) {
          assert.equal(expected, answer);
        });
    });
  });
});