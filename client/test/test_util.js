"use strict";

var assert = require("chai").assert;
var util = require("../src/util.js");
var BigInteger = require("../node_modules/openpgp/src/crypto/public_key/jsbn");

describe("util", function() {

  beforeEach(function() {});
  afterEach(function() {});

  describe("#bigInt2ByteString", function(){

    it("should return '0' when BigInt is 0" , function(){

      var bigInt = util.bigIntFromInt(1111);

      var result = util.bigInt2ByteString(bigInt);
      assert.equal("\u0004W", result);
    });

    var tests = [
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
