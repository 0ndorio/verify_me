"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _verifyme_utility = require("verifyme_utility");

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

/// TODO

var prepareBlinding = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(key_manager) {
    var public_key_package, curve, n, G, k, Ŕ, ŕ;
    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManager(key_manager));

            public_key_package = key_manager.get_primary_keypair().pub;
            curve = public_key_package.curve;
            n = curve.n;
            G = curve.G;
            k = null;
            Ŕ = null;
            ŕ = null;

          case 8:
            _context.next = 10;
            return _verifyme_utility.util.generateRandomScalar(curve);

          case 10:
            k = _context.sent;

            Ŕ = G.multiply(k);
            ŕ = Ŕ.affineX.mod(n);

          case 13:
            if (ŕ.compareTo(_verifyme_utility.BigInteger.ZERO) === 0) {
              _context.next = 8;
              break;
            }

          case 14:
            return _context.abrupt("return", { k: k, Ŕ: Ŕ });

          case 15:
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

/// TODO


function sign(message, k, key_manager) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(message));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManagerForEcdsaSign(key_manager));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isBigInteger(k));

  var ḿ = new _verifyme_utility.BigInteger(message, 32);

  var key_material = key_manager.get_primary_keypair();
  var n = key_material.pub.curve.n;
  var G = key_material.pub.curve.G;
  var d = key_material.priv.x;

  var Ŕ = G.multiply(k);
  var ŕ = Ŕ.affineX.mod(n);
  var dŕ = d.multiply(ŕ);
  var kḿ = k.multiply(ḿ);

  var ś = dŕ.add(kḿ).mod(n);

  return ś.toRadix(32);
}

var signing_ecdsa_api = {
  prepare: prepareBlinding,
  sign: sign
};

exports.default = signing_ecdsa_api;