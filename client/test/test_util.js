"use strict";

var assert = require("chai").assert;
var util = require("../src/util.js");
var BigInteger = require("../node_modules/openpgp/src/crypto/public_key/jsbn");

describe("util", function() {

  beforeEach(function() {});
  afterEach(function() {});

  describe("#bigInt2ByteString()", function() {

    var tests = [
      {arg: 1111, expected: "\u0004W"},
      {arg: 256,  expected: "\u0001\u0000"},
      {arg: 1,  expected: "\u0001"},
      {arg: 0,  expected: "\u0000"},
      {arg: -1,  expected: "ÿÿÿ"},
      {arg: -2,  expected: "ÿÿþ"},
      {arg: -256,  expected: "ÿÿ\u0000"},
      {arg: -1111,  expected: "ÿû©"}
    ];

    tests.forEach(function(test) {
      it("should return the byte string '" + test.expected + "' when input is BigInt with " + test.arg , function(){
        var bigInt = util.bigIntFromInt(test.arg);
        var result = util.bigInt2ByteString(bigInt);

        assert.equal(test.expected, result);
      });
    });

    tests = [
      {arg: "123", expected: null},
      {arg: 123,   expected: null},
      {arg: true,  expected: null},
      {arg: {},    expected: null},
      {arg: undefined, expected: null}
    ];

    tests.forEach(function(test) {
      it("should return 'null' when parameter is a " + typeof test.arg, function(){
        var result = util.bigInt2ByteString(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isString()", function() {

    var tests = [
      {arg: "123", expected: true},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false}
    ];

    tests.forEach(function(test) {

      it("should return '" + test.expected + "' when parameter is a " + typeof test.arg, function() {

        var result = util.isString(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });
});
