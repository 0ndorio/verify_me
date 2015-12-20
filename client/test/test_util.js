"use strict";

var assert = require("chai").assert;
var controls = require("./helper/helper").controls;
var client = require("../src/client");
var util = require("../src/util");

describe("util", function() {

  describe("#bigInt2Bytes()", function() {

    var tests = [
      {arg: 1111, expected: "\u0004W"},
      {arg: 256,  expected: "\u0001\u0000"},
      {arg: 1,  expected: "\u0001"},
      {arg: 0,  expected: "\u0000"},
      {arg: "",  expected: "\u0000"},
      {arg: -1,  expected: "ÿ"},
      {arg: -2,  expected: "þ"},
      {arg: -256,  expected: "ÿ\u0000"},
      {arg: -1111,  expected: "û©"}
    ];

    tests.forEach(function(test) {
      it("should return the byte string '" + test.expected + "' when input is BigInt with '" + test.arg + "'", function(){
        var bigInt = new util.BigInteger(test.arg.toString());
        var result = util.bigInt2Bytes(bigInt);

        assert.equal(test.expected, result);
      });
    });

    tests = [
      {arg: "123", expected: null},
      {arg: 123,   expected: null},
      {arg: true,  expected: null},
      {arg: {},    expected: null},
      {arg: null,    expected: null},
      {arg: undefined, expected: null}
    ];

    tests.forEach(function(test) {
      it("should return 'null' when parameter is a " + typeof test.arg, function(){
        var result = util.bigInt2Bytes(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#bytes2hex", function() {

    var tests = [
      {arg: null, expected: ""},
      {arg: "\u0000", expected: "00"},
      {arg: "\u000f", expected: "0f"},
      {arg: "\u0010", expected: "10"},
      {arg: "a", expected: "61"},
      {arg: "a\u0001", expected: "6101"}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when input is '" + escape(test.arg) + "'", function() {
        assert.equal(test.expected, util.bytes2hex(test.arg));
      });
    });
  });

  describe("#hex2bytes", function() {

    var tests = [
      {arg: null, expected: ""},
      {arg: "00", expected: "\u0000"},
      {arg: "0f", expected: "\u000f"},
      {arg: "10", expected: "\u0010"},
      {arg: "61", expected: "a"},
      {arg: "6101", expected: "a\u0001"}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when input is '" + escape(test.arg) + "'", function() {
        assert.equal(test.expected, util.hex2bytes(test.arg));
      });
    });
  });

  describe("#generateKeyFromString", function() {

    it("should return null if input is not a string", function() {
      assert.isNull(util.generateKeyFromString(123));
    });

    it("should return null if input string is not an ascii armored key", function() {
      assert.isNull(util.generateKeyFromString("a broken key"));
    });

    it("should return a {Key} object if input is a valid ascii armored key", function() {
      var keyString =
        ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
          'Version: GnuPG v2',
          '',
          'mI0EVmmWTQEEALumEkoJ2JTwSJ+U+aUrKmpAu0B6Rm5FKLagRC6sRrU/2RU12jBi',
          'q/c+SyJriC6Rfar73MXuaXmTOtkBfz6XkEV70FZVdavciZhEBIYzBvJDOuP4cyXA',
          'vwFa+pfn1myoW67JNHANkiSM5KJQXtOuvCtofH07lG5WiH2MuLGLImtDABEBAAG0',
          'G0pvaG4gRG9lIDxqb2huLmRvZUBmb28uY29tPoi3BBMBCAAhBQJWaZZNAhsDBQsJ',
          'CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEGs7P8KYU1e8x9gEAI+1rRdNtBCLou1R',
          'twaBDv/mMkmFfhcDqSk5TzK451cnOSI5YIm5IQFISjTdJm49v4h7UVJB0wNM4QKX',
          'bioX1e0AyOXTfqMHCfgZMpkbbMMvI4MBjp+hvQ/qByu3whsbVb0b4zJ1HPOoKc4o',
          'C/SCtSWGyTFV/YLRSBZEPEs/wyJnuI0EVmmWTQEEAL9VPU4uNMXgIGikhwkawDUw',
          'bgXWc/Cx/CSPbK+PXAGddTyrMWW9xrKvPrJfBiMq5kQlwD7IhCbmPu10h+brWZmj',
          'pXLxcWUWPnaWIXRR4f/lZSai6k7SZmTpKGXLLliO+Sna/uzBsgijAtOsK5EWEqj1',
          'FZzt1jSRApRarKcHgy6pABEBAAGInwQYAQgACQUCVmmWTQIbDAAKCRBrOz/CmFNX',
          'vAx9A/9A1atvnTlGj+lKh9VrlN5CZ4jZMMEsSy5iw311YNnAZhn4gMTMrbWrNyWI',
          '9PX2VpMxQHlT21l4OJgbof5gp7mOw0HdD0akMa0L3U4Ybd/JgloBDu9HUVB9mT0+',
          'CVKecnStCMounFvM2rc5uv9HcIgeLes4ccFJUzGSpeThYhyPEw==',
          '=w97z',
          '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

      var key = util.generateKeyFromString(keyString);
      assert.isNotNull(key);
      assert.isTrue(util.isOpenPGPKey(key));
    });
  });

  describe("#generateTwoPrimeNumbers", function() {

    this.timeout(0);

    it("should return a rejected Promise if input parameter is no integer", function() {
      return util.generateTwoPrimeNumbers(null)
        .then(function() { assert.fail(); })
        .catch(function(error) {
          assert.typeOf(error, "string");
        });
    });

    it("should throw an error when sth. wents wrong", function(done) {
      return util.generateTwoPrimeNumbers(7)
        .then(function(answer) {
          done(answer);
        })
        .catch(function(error) {
          assert.typeOf(error, "string");
          done();
        });
    });

    it("should return two {BigInteger} prime numbers of given bit length", function() {
      var bitLength = 256;

      return util.generateTwoPrimeNumbers(bitLength)
        .then(function(primeNumbers) {

          assert.equal(2, primeNumbers.length);

          primeNumbers.forEach(function(prime) {
            assert.isTrue(util.isBigInteger(prime));
            assert.isTrue(prime.isProbablePrime());
            assert.equal(bitLength, prime.bitLength());
          });

        });
    });
  });

  describe("#getTextAreaContent", function() {

    beforeEach(function() {
      controls.loadFixture("test/fixture/minimal.html");
    });

    it("should return null if input parameter is no string", function () {
      assert.isNull(util.getTextAreaContent(123));
    });

    it("should return null if input id does not exists", function () {
      assert.isNull(util.getTextAreaContent("myNonExistingID"));
    });

    it("should return a string with the textarea content if input id exists", function() {
      var string = "123";
      controls.userPublicKeyString = string;

      var result = util.getTextAreaContent(client.user_public_key_element_id);
      assert.isTrue(util.isString(result));
      assert.equal(string, result);
    });
  });

  describe("#hashMessage()", function() {

    it("should return null if input parameter is no string", function () {
      assert.isNull(util.hashMessage(123));
    });

    it("should return a hash digest with bit length 512", function() {
      var expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
      var result = util.hashMessage("abc");

      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });

  describe("#int2BigInt()", function() {

    var tests = [
      {arg: "123"}, {arg: true}, {arg: {}}, {arg: null}, {arg: undefined}, {arg: 123.12}
    ];

    tests.forEach(function(test) {
      it("should return 'null' when parameter is a " + typeof test.arg, function(){
        assert.equal(test.expected, util.int2BigInt(test.arg));
      });
    });

    it("should return a 'BigInteger' when parameter is an integer", function() {
      assert.instanceOf(util.int2BigInt(0), util.BigInteger);
    });

    tests = [
      {arg: 0},
      {arg: 1}, {arg: -1},
      {arg: util.BigInteger.ZERO.DV}, {arg: -util.BigInteger.ZERO.DV}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.arg + "' when parameter is " + test.arg, function() {
        assert.equal(test.arg, util.int2BigInt(test.arg));
      });
    });
  });

  describe("#isBigInteger()", function() {

    var tests = [
      {arg: "123", expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: util.BigInteger.ONE, expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", function() {
        var result = util.isBigInteger(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isInteger()", function() {

    var tests = [
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: "123", expected: false},
      {arg: 123,   expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", function() {
        var result = util.isInteger(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isKeyReadSuccessful()", function() {

    var tests = [
      {arg: null, expected: false},
      {arg: undefined, expected: false},
      {arg: [], expected: false},
      {arg: {}, expected: false},
      {arg: {"err": 1}, expected: false},
      {arg: {"err": 1, "keys": 1}, expected: false},
      {arg: {"keys": 1}, expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is " + test.arg, function() {
        var result = util.isKeyReadSuccessful(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isObject()", function() {

    var tests = [
      {arg: undefined, expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: "123", expected: false},
      {arg: {},    expected: true},
      {arg: [],    expected: true},
      {arg: function(){}, expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", function() {
        var result = util.isObject(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isOpenPGPKey()", function() {

    var keyString =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2',
        '',
        'mI0EVmmWTQEEALumEkoJ2JTwSJ+U+aUrKmpAu0B6Rm5FKLagRC6sRrU/2RU12jBi',
        'q/c+SyJriC6Rfar73MXuaXmTOtkBfz6XkEV70FZVdavciZhEBIYzBvJDOuP4cyXA',
        'vwFa+pfn1myoW67JNHANkiSM5KJQXtOuvCtofH07lG5WiH2MuLGLImtDABEBAAG0',
        'G0pvaG4gRG9lIDxqb2huLmRvZUBmb28uY29tPoi3BBMBCAAhBQJWaZZNAhsDBQsJ',
        'CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEGs7P8KYU1e8x9gEAI+1rRdNtBCLou1R',
        'twaBDv/mMkmFfhcDqSk5TzK451cnOSI5YIm5IQFISjTdJm49v4h7UVJB0wNM4QKX',
        'bioX1e0AyOXTfqMHCfgZMpkbbMMvI4MBjp+hvQ/qByu3whsbVb0b4zJ1HPOoKc4o',
        'C/SCtSWGyTFV/YLRSBZEPEs/wyJnuI0EVmmWTQEEAL9VPU4uNMXgIGikhwkawDUw',
        'bgXWc/Cx/CSPbK+PXAGddTyrMWW9xrKvPrJfBiMq5kQlwD7IhCbmPu10h+brWZmj',
        'pXLxcWUWPnaWIXRR4f/lZSai6k7SZmTpKGXLLliO+Sna/uzBsgijAtOsK5EWEqj1',
        'FZzt1jSRApRarKcHgy6pABEBAAGInwQYAQgACQUCVmmWTQIbDAAKCRBrOz/CmFNX',
        'vAx9A/9A1atvnTlGj+lKh9VrlN5CZ4jZMMEsSy5iw311YNnAZhn4gMTMrbWrNyWI',
        '9PX2VpMxQHlT21l4OJgbof5gp7mOw0HdD0akMa0L3U4Ybd/JgloBDu9HUVB9mT0+',
        'CVKecnStCMounFvM2rc5uv9HcIgeLes4ccFJUzGSpeThYhyPEw==',
        '=w97z',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

    var tests = [
      {arg: undefined, expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: "123", expected: false},
      {arg: {},    expected: false},
      {arg: [],    expected: false},
      {arg: util.generateKeyFromString(keyString), expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", function() {
        var result = util.isOpenPGPKey(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isString()", function() {

    var tests = [
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: "123", expected: true}
    ];

    tests.forEach(function(test) {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", function() {
        var result = util.isString(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#str2BigInt()", function() {

    it("should return null if input not a string", function() {
      assert.isNull(util.str2BigInt(123));
    });

    it("should return a BigInteger object if input a string", function() {
      var input = "message";
      var result = util.str2BigInt(input);

      assert.instanceOf(result, util.BigInteger);
    });

    it("should be able to convert ascii encoded messages", function() {
      var input = "--- my ascii encoded message ---";
      var result = util.str2BigInt(input);

      assert.equal(input, result.toBuffer().toString("utf8"));
      assert.equal(input, result.toBuffer().toString("binary"));
      assert.equal(input, result.toBuffer().toString("ascii"));
      assert.notEqual(input, result.toBuffer().toString("hex"));
      assert.notEqual(input, result.toBuffer().toString("base64"));
    });
  });
});
