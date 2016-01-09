"use strict";

import { assert } from "chai"
import * as kbpgp from "kbpgp"
import * as sinon from "sinon"

import * as client from "../src/client"
import * as util from "../src/util"
import RsaBlindingContext from "../src/blinding/rsa/blinding_context_rsa"
import EcdsaBlindingContext from "../src/blinding/ecdsa/blinding_context_ecdsa"

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
});