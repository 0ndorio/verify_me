"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"
import * as sinon from "sinon"

import * as client from "../src/client"
import * as util from "../src/util"
import RSABlindingContext from "../src/types/rsa_blinding_context"
import ECCBlindingContext from "../src/types/ecc_blinding_context"

import { controls } from "./helper/client_control"
import sample_keys from "./helper/keys"

describe("client", function() {

  beforeEach(() => {
    controls.loadFixture("test/fixture/keys_2048bit.html");

    this.server = sinon.fakeServer.create();
    this.server.autoRespond = true;
  });

  afterEach(() => {
    this.server.restore();
  });

  ///---------------------------------
  /// #getPublicKey()
  ///---------------------------------

  describe("#getPublicKey()", () => {

    it ("should return users public key as kbpgp.Key", () => {
      return client.getPublicKey()
        .then(key => assert.instanceOf(key, kbpgp.KeyManager));
    });

    it ("must return a rejected promise if id is missing from html", () => {
      controls.loadFixture("test/fixture/missing_id.html");
      return client.getPublicKey()
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("must return a rejected promise if string is no key representation", () => {
      controls.userPublicKeyString = "123";

      return client.getPublicKey()
        .catch(error => assert.instanceOf(error, Error));
    });
  });

  ///---------------------------------
  /// #getPublicKeyString()
  ///---------------------------------

  describe("#getPublicKeyString()", () => {

    it ("should return null if id is missing from html", () => {
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

    for (const test of tests) {
      it ("should trim the input string", () => {
        controls.userPublicKeyString = test.arg;
        assert.equal(test.expected, client.getPublicKeyString());
      });
    }
  });

  ///---------------------------------
  /// #getToken()
  ///---------------------------------

  describe("#getToken()", () => {

    it ("should return Token as BigInteger", () => {
      const token = client.getToken();
      assert.isTrue(util.isBigInteger(token));
    });

    it ("result must pass prime test", () => {
      const token = client.getToken();
      assert.isTrue(token.isProbablePrime());
    });

    it ("must throw if id is missing from html", () => {
      controls.loadFixture("test/fixture/missing_id.html");
      assert.throws(() => {client.getToken()}, Error);
    });

    it ("must throw if Token is not prime", () => {
      controls.userTokenString = "A";
      assert.throws(() => {client.getToken()}, Error);
    });
  });

  ///---------------------------------
  /// #getTokenString()
  ///---------------------------------

  describe("#getTokenString()", () => {

    it ("should return null if id is missing from html", () => {
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

    for (const test of tests) {
      it ("should trim the input string", () => {
        controls.userTokenString = test.arg;
        assert.equal(test.expected, client.getTokenString());
      });
    }
  });

  ///---------------------------------
  /// #getServerPublicKey()
  ///---------------------------------

  describe("#getServerPublicKey()", () => {

    it ("should return server public key as kbpgp.Key", () => {
      return client.getServerPublicKey()
        .then(key => assert.instanceOf(key, kbpgp.KeyManager));
    });

    it ("must throw if id is missing from html",() => {
      controls.loadFixture("test/fixture/missing_id.html");
      return client.getPublicKey()
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("must throw if string is no key representation",() => {
      controls.serverPublicKey = "123";
      return client.getPublicKey()
        .catch(error => assert.instanceOf(error, Error));
    });
  });

  ///---------------------------------
  /// #getServerPublicKeyString()
  ///---------------------------------

  describe("#getServerPublicKeyString()", () => {

    it ("should return null if id is missing from html",() => {
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

    for (const test of tests) {
      it ("should trim the input string", () => {
        controls.serverPublicKey = test.arg;
        assert.equal(test.expected, client.getServerPublicKeyString());
      });
    }
  });

  ///---------------------------------
  /// #getTextAreaContent()
  ///---------------------------------

  describe("#getTextAreaContent", () => {

    beforeEach(() => {
      controls.loadFixture("test/fixture/minimal.html");
    });

    it("should return null if input parameter is no string", () => {
      assert.isNull(client.getTextAreaContent(123));
    });

    it("should return null if input id does not exists", () => {
      assert.isNull(client.getTextAreaContent("myNonExistingID"));
    });

    it("should return a string with the textarea content if input id exists", () => {
      const string = "123";
      controls.userPublicKeyString = string;

      const result = client.getTextAreaContent(client.user_public_key_element_id);
      assert.isTrue(util.isString(result));
      assert.equal(string, result);
    });
  });

  ///---------------------------------
  /// #generateBlindingContext()
  ///---------------------------------

  describe("#generateBlindingContext()", () => {

    const token = new util.BigInteger("3", 16);

    it ("should return a rejected promise if input is no {KeyManager} object", () => {
      return client.generateBlindingContext(123, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return a rejected promise if key algorithm is encryption only key", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      key.primary.key.type = kbpgp.const.openpgp.public_key_algorithms.RSA_ENCRYPT_ONLY;

      return client.generateBlindingContext(key, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return a rejected promise if key algorithm is unknown", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      key.primary.key.type = -1;

      return client.generateBlindingContext(key, token)
        .catch(error => assert.instanceOf(error, Error));
    });

    it ("should return an RSABlindingContext if input is a rsa key", async () => {
      const key = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      return client.generateBlindingContext(key, token)
        .then(context => assert.instanceOf(context, RSABlindingContext));
    });

    it ("should return an ECCBlindingContext if input is a ecc key", async () => {
      const key = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
      return client.generateBlindingContext(key, token)
        .then(context => assert.instanceOf(context, ECCBlindingContext));
    });
  });

  ///---------------------------------
  /// #sendBlindingRequest()
  ///---------------------------------

  describe("#sendBlindingRequest()", () => {

    it("should return a promise", () => {
      const task = client.sendBlindingRequest().catch(() => {});
      assert.instanceOf(task, Promise);
    });

    it("should reject with wrong typed input for blinded_message", (done) => {

      return client.sendBlindingRequest(123)
        .catch(() => done());
    });

    it("should reject with wrong typed input for blinding_context", (done) => {

      const context = new RSABlindingContext();
      context.hashed_token = 123;

      return client.sendBlindingRequest("1234", context)
        .catch(() => done());
    });

    it("should reject when a network error occurred", async () => {

      const context = new RSABlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      const request_promise = client.sendBlindingRequest(util.BigInteger.ZERO, context)
        .catch(error => assert.instanceOf(error, Error));

      assert.equal(1, this.server.requests.length);
      this.server.requests[0].onload = null;
      this.server.requests[0].abort();

      return request_promise;
    });

    it("should reject and return status text error if status is not 200", (done) => {

      const expected = { code: 404, status_text: new Error("Not Found") };
      this.server.respondWith([expected.code, { "Content-Type": "text/plain" }, ""]);

      let context = new RSABlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      return client.sendBlindingRequest(util.BigInteger.ZERO , context)
        .catch(() => done());
    });

    it("should resolve and return server response if status is 200", () => {

      const expected = "deadbeef";
      this.server.respondWith([200, { "Content-Type": "text/plain" }, expected]);

      let context = new RSABlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      return client.sendBlindingRequest(util.BigInteger.ZERO , context)
        .then(answer => assert.equal(expected, answer.toRadix(16)));
    });
  });
});