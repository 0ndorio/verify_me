"use strict";

import { assert } from "chai"
import { ecc } from "kbpgp"

import { BigInteger, Buffer } from "../src/types"
import check from "../src/check"
import util from "../src/util"

import keys, { public_keys} from "./helper/keys"

describe("check", function() {

  ///---------------------------------
  /// #assert()
  ///---------------------------------

  describe("#assert", () => {

    it("nothing should happen when condition validates to true", () => {
      assert(true);
    });

    it("should throw if condition validates to false", () => {
      assert.throws(() => assert(false));
    });

    it("should throw with custom message if condition validates to false", () => {
      const custom_message = "custom message";
      assert.throws(() => assert(false, custom_message), custom_message);
    });
  });

  ///---------------------------------
  /// #isBigInteger()
  ///---------------------------------

  describe("#isBigInteger()", () => {

    it("should return false when parameter is a no {BigInteger}", () => {
      assert.isFalse(check.isBigInteger(123));
    });

    it ("should return true when input parameter is a valid {BigInteger}", () => {
      assert.isTrue(check.isBigInteger(BigInteger.ZERO));
    });
  });

  ///---------------------------------
  /// #isBuffer()
  ///---------------------------------

  describe("#isBuffer()", () => {

    it("should return false when parameter is a no {Buffer}", () => {
      assert.isFalse(check.isBuffer(123));
    });

    it ("should return true when input parameter is a valid {Buffer}", () => {
      assert.isTrue(check.isBuffer(new Buffer(123)));
    });
  });

  ///---------------------------------
  /// #isCurve()
  ///---------------------------------

  describe("#isCurve()", () => {

    it("should return false when parameter is a no {Curve}", () => {
      assert.isFalse(check.isCurve(123));
    });

    it ("should return true when input parameter is a valid {Curve}", () => {
      assert.isTrue(check.isCurve(ecc.curves.brainpool_p512()));
    });
  });

  ///---------------------------------
  /// #isFunction()
  ///---------------------------------

  describe("#isFunction()", () => {

    it ("should return false when input parameter is not a valid {function}", () => {
      assert.isFalse(check.isFunction(123));
    });

    it ("should return true when input parameter is a valid {function}", () => {
      assert.isTrue(check.isFunction(() => {}));
    });
  });

  ///---------------------------------
  /// #isInteger()
  ///---------------------------------

  describe("#isInteger()", () => {

    it ("should return false when input parameter is not a valid integer {number}", () => {
      assert.isFalse(check.isInteger("123"));
    });

    it ("should return true when input parameter is a valid integer {number}", () => {
      assert.isTrue(check.isInteger(123));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManager({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(public_keys[0]);
      assert.isTrue(check.isKeyManager(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManagerForEcdsaSign()
  ///---------------------------------

  describe("#isKeyManagerForEcdsaSign()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManagerForEcdsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(keys.ecc.bp[512].pub);
      assert.isTrue(check.isKeyManagerForEcdsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(check.isKeyManagerForRsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(keys.rsa[1024].pub);
      assert.isTrue(check.isKeyManagerForRsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isObject()
  ///---------------------------------

  describe("#isObject()", () => {

    it("should return false when parameter is not an {object}", () => {
      assert.isFalse(check.isObject(123));
    });

    it("should return true when parameter is an {object}", () => {
      assert.isTrue(check.isObject({}));
    });
  });

  ///---------------------------------
  /// #isPoint()
  ///---------------------------------

  describe("#isPoint()", () => {

    it("should return false when parameter is not a {Point}", () => {
      assert.isFalse(check.isPoint(123));
    });

    it("should return true when parameter is a {Point}", () => {
      assert.isTrue(check.isPoint(ecc.curves.brainpool_p512().G));
    });
  });

  ///---------------------------------
  /// #isString()
  ///---------------------------------

  describe("#isString()", () => {

    it("should return false when parameter is not a {string}", () => {
      assert.isFalse(check.isString(123));
    });

    it("should return true when parameter is a {string}", () => {
      assert.isTrue(check.isString("123"));
    });
  });
});
