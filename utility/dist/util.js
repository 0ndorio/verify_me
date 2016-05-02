"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});


/**
 * Generate a random scalar k.
 *
 * k is in range [1, n-1] where n is the prime number defining
 * the order of the givens curves base point.
 *
 * @param {Curve} curve
 *    The curve we use to generate the random scalar value.
 * @returns {Promise}
 *    The promise of a {BigInteger} scalar [1, n-1]
 */

var generateRandomScalar = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(curve) {
    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            (0, _check.assert)(_check2.default.isCurve(curve));

            return _context.abrupt("return", new Promise(function (resolve, reject) {
              return curve.random_scalar(function (k) {

                // assert [1, n-1]
                (0, _check.assert)(k.compareTo(_types.BigInteger.ZERO) >= 0);
                (0, _check.assert)(k.compareTo(curve.n) < 0);

                resolve(k);
              });
            }));

          case 2:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function generateRandomScalar(_x) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Generates a blinding factor for the rsa blinding algorithm.
 *
 * @param {number} bitLength
 *    The target blinding factor length in bit.
 * @returns {BigInteger}
 *    the requested blinding factor.
 */


var generateRsaBlindingFactor = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee2(bitLength) {
    var sub_prime_length, primes;
    return regeneratorRuntime.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            (0, _check.assert)(_check2.default.isInteger(bitLength), "The blinding factor bit length is no integer but a '" + bitLength + "'");
            (0, _check.assert)(bitLength % 8 === 0 && bitLength >= 256 && bitLength <= 16384, "The blinding factor bit length must be a multiple of 8 bits and >= 256 and <= 16384");

            sub_prime_length = Math.floor(bitLength / 2);
            _context2.next = 5;
            return generateTwoPrimeNumbers(sub_prime_length);

          case 5:
            primes = _context2.sent;
            return _context2.abrupt("return", primes[0].multiply(primes[1]));

          case 7:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2, this);
  }));

  return function generateRsaBlindingFactor(_x2) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Generate two prime numbers with n bits using the rsa.generate()
 * in lack of a real generatePrime() method.
 *
 * @param {number} primeBitLength
 *    The target prime number length in bit.
 * @returns {Promise}
 *    The promise of two prime numbers with the requesterd bit length.
 */


var _kbpgp = require("kbpgp");

var kbpgp = _interopRequireWildcard(_kbpgp);

var _check = require("./check");

var _check2 = _interopRequireDefault(_check);

var _types = require("./types");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Converts a given armored key string into a kbpgp {KeyManager} object.
 *
 * @param {string} key_as_string
 *    An ascii armored key string.
 * @returns {Promise}
 *    The promise of a {KeyManager} object.
 */
function generateKeyFromString(key_as_string) {
  return new Promise(function (resolve, reject) {

    (0, _check.assert)(_check2.default.isString(key_as_string), "Input parameter is not of type string.");

    _types.KeyManager.import_from_armored_pgp({ armored: key_as_string }, function (err, key_manager) {
      if (err) {
        reject(err);
      } else {
        resolve(key_manager);
      }
    });
  });
}function generateTwoPrimeNumbers(primeBitLength) {
  return new Promise(function (resolve, reject) {

    (0, _check.assert)(_check2.default.isInteger(primeBitLength), "The prime bit length is no integer but a '" + primeBitLength + "'");
    (0, _check.assert)(primeBitLength % 8 === 0 && primeBitLength >= 128 && primeBitLength <= 8192, "The prime bit length must be a multiple of 8 bits and >= 128 and <= 8192");

    var key_arguments = {
      e: 65537,
      nbits: primeBitLength * 2
    };

    kbpgp.asym.RSA.generate(key_arguments, function (err, key) {
      if (err) {
        reject(err);
      }

      resolve([key.priv.p, key.priv.q]);
    });
  });
}

/**
 * Hashes the given message with sha512 and returns the digest.
 *
 * @param {BigInteger} message
 *    Input parameter to hash.
 * @returns {BigInteger}
 *    Hash digest as {string} or {null} if input message is no string object.
 */
function calculateSha512(message) {
  (0, _check.assert)(_check2.default.isBigInteger(message));

  var hash_buffer = kbpgp.hash.SHA512(message.toBuffer());
  return _types.BigInteger.fromBuffer(hash_buffer);
}

var util_api = {
  generateKeyFromString: generateKeyFromString,
  generateRandomScalar: generateRandomScalar,
  generateRsaBlindingFactor: generateRsaBlindingFactor,
  generateTwoPrimeNumbers: generateTwoPrimeNumbers,
  calculateSha512: calculateSha512
};

exports.default = util_api;