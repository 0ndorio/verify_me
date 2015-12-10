"use strict";

var assert = require("chai").assert;
var BigInteger = require("../node_modules/kbpgp/lib/bn").BigInteger;
var controls = require("./helper/helper").controls;
var client = require("../src/client");
var kbpgp = require("kbpgp");
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
        var bigInt = new BigInteger(test.arg.toString());
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

  describe("#bytes2MPI", function() {

    it("should return null if input is no string", function () {
      assert.isNull(util.bytes2MPI(123));
    });

    it("should return valid mpi with data if input is byte string", function () {
      var input = "123";
      var result = util.bytes2MPI(input);

      assert.isTrue(util.isMPIWithData(result));
      assert.equal(input, result.data.toBuffer().toString("binary"));
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
         'Version: SKS 1.1.3',
         '',
         'mQENAy9J/w4AAAEIALBDDD4vWqG/Jg59ghhMYAa+E7ECCTv2At8hxsM5cMP8P9sMLjs+GMfD',
         'IdQSOqlQXbunYADvM1l/h2fOuUMoYFIIGaUsO5Daxvd9uWceM4DVzhXMeJZb9wc5jEJEF21+',
         'qidKj5OGsMyTrg++mn4Gh/aFXvvy3N3KWaQpPfNi3NRZUpNLz0IlfbXVBQGD6reLoxPptJun',
         'NqpClyRiesgq8HCscmB2oQo+b9KzSSgzU9qQJA4SljMYVmJ2sDE/sjREI8iKL8lIgUMhJG9q',
         'NggWjuxFTpVcGKkuQFJIvdL+UhTVvEBuqw6n4cmFAzfZ/AInJM032qLtsaIf5begFKI3up0A',
         'BRGJARUDBSAxm7HC5begFKI3up0BAbdDB/0TOcI0ec+OPxC5RTZAltgIgyUc0yOjHoTD/yBh',
         'WjZdQ9YVrLGMWTW4fjhm4rFnppVZKS/N71bwI76SnN9zO4pPfx86aQPR7StmSLJxB+cfh2GL',
         'gudJoG9ifhJWdNYMUD/yhA0TpJkdHMD5yTDE5Ce/PqKLviiX9C5MPW0AT1MDvafQlzeUXfb5',
         '1a71vQNPw7W1NBAVZRwztm7TNUaxWMFuOmUtOJpq4F/qDQTIHW2zGPJvl47rpf6JSiyIyU70',
         'l0deiQcZOXPC80tgInhNoBrz3zbEXhXRJo1fHkr2YSLclpJaoUOHsPxoyrNB28ASL5ZknPwI',
         'Zx3+cFxaGpRprfSdtCFKb2huIEEuIFBlcnJ5IDxwZXJyeUBwaG9lbml4Lm5ldD6JARUDBRAv',
         'Sf8k5begFKI3up0BAcbGB/0eLod2qrQxoE2/RUWQtqklOPUj/p/ZTmvZm8BgsdIflb0AMeey',
         '9o8AbxyAgA3pcrcCjcye79M1Ma2trEvRksvs8hViuq3BXXjDbjPZi3wTtKSvbAC022OV52Sb',
         '8/sgiTGp7xC8QMqS8w4ZeKoxJGh1TVMYrevUA8a2Rr5aDqrR3EA4rifSHwkVjJWOPF69xiKt',
         'IVA0LcYJvGsPOQCf2ag+nOcnDrF4dvcmg6XZ/RyLepve+1qkhXsA/oq+yHoaqWfe+bwgssk/',
         'qw1aEUk7Di8x7vY+cfjvWaazcYGw8kkIwSSqqIq0pkKFz2xDDfSaDJl6OW/2GUK0wDpJmYZo',
         'PN40iJUDBRAvSgDsU5OkROGu2G8BAeUqBACbC45t4+wYxWCxxp81pkFRb8RWBvEvbXI+Spwd',
         '4NcKs8jc5OVC8V02yiq4KbKFDRxdw2OWpUCSRAJe1gjsfFrZ+2RivpKk06kbAYthES03MjXg',
         'cfcV3z2d7IWanJzdcOlzsHzPe1+RoUAaqBjvcqPRCGRlk0ogkYHyWYxElc6574iVAwUQL9iL',
         'CXr7ES8bepftAQGPywP/d9GSpEmS7LLIqazl4rgN1nkXN5KqduiH8Whu3xcBrdOAn7IYnGTp',
         'O+Ag4qwKKH+y/ke9CeZL6AnrU9c0pux150dHsDeHtpTPyInkjgKI7BofprydvpiFNd0nlAi4',
         'J4SAEYr3q92Qn/IiKpnLgo6Ls/GFb7q6y1O/2LL8PC2zrYU=',
         '=eoGb',
         '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

      var key = util.generateKeyFromString(keyString);
      assert.isNotNull(key);
      assert.isTrue(util.isKeyReadSuccessful(key));

      assert.instanceOf(key.keys[0], kbpgp.key.Key);
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

      assert.equal(512, result.length * 8);
      assert.equal(expected_hex, util.bytes2hex(result));
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
      assert.instanceOf(util.int2BigInt(0), BigInteger);
    });

    tests = [
      {arg: 0},
      {arg: 1}, {arg: -1},
      {arg: BigInteger.ZERO.DV}, {arg: -BigInteger.ZERO.DV}
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
      {arg: BigInteger.ONE, expected: true}
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

  describe("#isMPIProbablyPrime()", function() {

    it("should return false if input parameter is no mpi", function () {
      assert.isFalse(util.isMPIProbablyPrime(123));
    });

    it("should return false if input mpi parameter is not prime", function () {
      var mpi = util.bytes2MPI("10");
      assert.isFalse(util.isMPIProbablyPrime(mpi));
    });

    it("should return true if input mpi parameter is a small prime", function () {
      var prime = new BigInteger("7");
      var mpi = { data: prime };
      assert.isTrue(util.isMPIProbablyPrime(mpi));
    });

    it("should return true if input mpi parameter is a large prime", function () {
      var prime = new BigInteger("2039568783564019774057658669290345772801939933"+
                                 "1434826309477264645328306272270127763293661606"+
                                 "3144088173312372882677123879538709400158306567"+
                                 "3383282791544996983660719067664400370742171178"+
                                 "0569087279284814911202228633214487618337632651"+
                                 "2083574821647933992961249917319836219304274280"+
                                 "243803104015000563790123");
      var mpi = { data: prime };
      assert.isTrue(util.isMPIProbablyPrime(mpi));
    });
  });

  describe("#isMPIWithData()", function() {

    it("should return false if input parameter is no mpi", function () {
      assert.isFalse(util.isMPIWithData(123));
    });

    it("should return false if input mpi parameter has no data", function () {
      assert.isFalse(util.isMPIWithData({}));
    });

    it("should return true if input mpi parameter has data", function () {
      var mpi = util.bytes2MPI("\u0000");
      assert.isTrue(util.isMPIWithData(mpi));
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
        'Version: SKS 1.1.3',
        '',
        'mQENAy9J/w4AAAEIALBDDD4vWqG/Jg59ghhMYAa+E7ECCTv2At8hxsM5cMP8P9sMLjs+GMfD',
        'IdQSOqlQXbunYADvM1l/h2fOuUMoYFIIGaUsO5Daxvd9uWceM4DVzhXMeJZb9wc5jEJEF21+',
        'qidKj5OGsMyTrg++mn4Gh/aFXvvy3N3KWaQpPfNi3NRZUpNLz0IlfbXVBQGD6reLoxPptJun',
        'NqpClyRiesgq8HCscmB2oQo+b9KzSSgzU9qQJA4SljMYVmJ2sDE/sjREI8iKL8lIgUMhJG9q',
        'NggWjuxFTpVcGKkuQFJIvdL+UhTVvEBuqw6n4cmFAzfZ/AInJM032qLtsaIf5begFKI3up0A',
        'BRGJARUDBSAxm7HC5begFKI3up0BAbdDB/0TOcI0ec+OPxC5RTZAltgIgyUc0yOjHoTD/yBh',
        'WjZdQ9YVrLGMWTW4fjhm4rFnppVZKS/N71bwI76SnN9zO4pPfx86aQPR7StmSLJxB+cfh2GL',
        'gudJoG9ifhJWdNYMUD/yhA0TpJkdHMD5yTDE5Ce/PqKLviiX9C5MPW0AT1MDvafQlzeUXfb5',
        '1a71vQNPw7W1NBAVZRwztm7TNUaxWMFuOmUtOJpq4F/qDQTIHW2zGPJvl47rpf6JSiyIyU70',
        'l0deiQcZOXPC80tgInhNoBrz3zbEXhXRJo1fHkr2YSLclpJaoUOHsPxoyrNB28ASL5ZknPwI',
        'Zx3+cFxaGpRprfSdtCFKb2huIEEuIFBlcnJ5IDxwZXJyeUBwaG9lbml4Lm5ldD6JARUDBRAv',
        'Sf8k5begFKI3up0BAcbGB/0eLod2qrQxoE2/RUWQtqklOPUj/p/ZTmvZm8BgsdIflb0AMeey',
        '9o8AbxyAgA3pcrcCjcye79M1Ma2trEvRksvs8hViuq3BXXjDbjPZi3wTtKSvbAC022OV52Sb',
        '8/sgiTGp7xC8QMqS8w4ZeKoxJGh1TVMYrevUA8a2Rr5aDqrR3EA4rifSHwkVjJWOPF69xiKt',
        'IVA0LcYJvGsPOQCf2ag+nOcnDrF4dvcmg6XZ/RyLepve+1qkhXsA/oq+yHoaqWfe+bwgssk/',
        'qw1aEUk7Di8x7vY+cfjvWaazcYGw8kkIwSSqqIq0pkKFz2xDDfSaDJl6OW/2GUK0wDpJmYZo',
        'PN40iJUDBRAvSgDsU5OkROGu2G8BAeUqBACbC45t4+wYxWCxxp81pkFRb8RWBvEvbXI+Spwd',
        '4NcKs8jc5OVC8V02yiq4KbKFDRxdw2OWpUCSRAJe1gjsfFrZ+2RivpKk06kbAYthES03MjXg',
        'cfcV3z2d7IWanJzdcOlzsHzPe1+RoUAaqBjvcqPRCGRlk0ogkYHyWYxElc6574iVAwUQL9iL',
        'CXr7ES8bepftAQGPywP/d9GSpEmS7LLIqazl4rgN1nkXN5KqduiH8Whu3xcBrdOAn7IYnGTp',
        'O+Ag4qwKKH+y/ke9CeZL6AnrU9c0pux150dHsDeHtpTPyInkjgKI7BofprydvpiFNd0nlAi4',
        'J4SAEYr3q92Qn/IiKpnLgo6Ls/GFb7q6y1O/2LL8PC2zrYU=',
        '=eoGb',
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

    it("should return null if input not a base 10 integer string", function() {
      assert.isNull(util.str2BigInt("caffee"));
    });

    it("should return a BigInteger object if input a valid base 10 integer string", function() {
      var input = "11242";
      var result = util.str2BigInt(input);

      assert.instanceOf(result, BigInteger);
      assert.equal(input, result.toString());
    });
  });
});
