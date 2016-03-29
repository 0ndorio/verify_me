"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _verifyme_utility = require("verifyme_utility");

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/**
 * Prepares the ECDSA blinding algorithm through
 * the creation of request individual secret scalar
 * values and the related public points.
 *
 * @param {KeyManager} key_manager
 *    A {KeyManager} containing an ECC based key to
 *    extract the related curves public information.
 * @returns {{p: number, P: Point, q: number, Q: Point}}
 *    The request secret scalars p, q
 *    and the related public points P, Q.
 */

var prepareBlinding = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(key_manager) {
    var public_key_package, curve, n, G, p, q, p_inv, P, Q;
    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManager(key_manager));

            public_key_package = key_manager.get_primary_keypair().pub;
            curve = public_key_package.curve;
            n = curve.n;
            G = curve.G;
            _context.next = 7;
            return _verifyme_utility.util.generateRandomScalar(curve);

          case 7:
            p = _context.sent;
            _context.next = 10;
            return _verifyme_utility.util.generateRandomScalar(curve);

          case 10:
            q = _context.sent;
            p_inv = p.modInverse(n);
            P = G.multiply(p_inv);

            (0, _verifyme_utility.assert)(curve.isOnCurve(P));

            Q = G.multiply(p_inv).multiply(q);

            (0, _verifyme_utility.assert)(curve.isOnCurve(Q));

            return _context.abrupt("return", { p: p, P: P, q: q, Q: Q });

          case 17:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function prepareBlinding(_x) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Signs the given blinded message.
 *
 * @param {string} message
 *    The message to sign.
 * @param {object.<number, number>}secret_scalars
 *    The scalar values created during initialization.
 * @param {KeyManager} key_manager
 *    The {KeyManager} containing the ecc based key
 *    that will be used to sign the message.
 * @returns {string}
 *    The signed message.
 */


function sign(message, secret_scalars, key_manager) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(message));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManagerForEcdsaSign(key_manager));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isObject(secret_scalars));
  (0, _verifyme_utility.assert)(secret_scalars.hasOwnProperty("p") && _verifyme_utility.check.isBigInteger(secret_scalars.p));
  (0, _verifyme_utility.assert)(secret_scalars.hasOwnProperty("q") && _verifyme_utility.check.isBigInteger(secret_scalars.q));

  var public_key_package = key_manager.get_primary_keypair().pub;
  var n = public_key_package.curve.n;

  var m = new _verifyme_utility.BigInteger(message, 32);
  var p = secret_scalars.p;
  var q = secret_scalars.q;

  var signed_blinded_message = p.multiply(m).add(q).mod(n);
  return signed_blinded_message.toRadix(32);
}

var signing_ecdsa_api = {
  prepare: prepareBlinding,
  sign: sign
};

exports.default = signing_ecdsa_api;