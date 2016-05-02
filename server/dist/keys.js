"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});


/**
 * Loads and unlocks a key pair.
 *
 * @param {string} public_key_path
 *    Path to the public key.
 * @param {string} private_key_path
 *    Path to the private key.
 * @param {string} passphrase
 *    Passphrase to unlock the private key.
 * @returns {Promise.<KeyManager>}
 *    The promise of a {KeyManager] that contains
 *    the key objects.
 */

var loadKey = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(public_key_path, private_key_path) {
    var passphrase = arguments.length <= 2 || arguments[2] === undefined ? null : arguments[2];
    var public_key_string, private_key_string, key_manager;
    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(public_key_path));
            (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(private_key_path));

            public_key_string = _fs2.default.readFileSync(public_key_path, "utf-8");
            private_key_string = _fs2.default.readFileSync(private_key_path, "utf-8");
            _context.next = 6;
            return _verifyme_utility.util.generateKeyFromString(public_key_string);

          case 6:
            key_manager = _context.sent;
            _context.next = 9;
            return mergePrivateKeyIntoKeyManager(key_manager, private_key_string);

          case 9:
            if (!passphrase) {
              _context.next = 13;
              break;
            }

            (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(passphrase));
            _context.next = 13;
            return unlockPrivateKeyInKeyManager(key_manager, passphrase);

          case 13:
            return _context.abrupt("return", key_manager);

          case 14:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function loadKey(_x, _x2, _x3) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Helper to merge a private key into a given public key containing {KeyManager}.
 *
 * @param {KeyManager} key_manager
 *    A public key containing {KeyManager}.
 * @param {string} private_key_string
 *    Path to the private key.
 * @returns {Promise.<KeyManager>}
 *    Promise of a {KeyManager} containing both keys.
 */


var _fs = require("fs");

var _fs2 = _interopRequireDefault(_fs);

var _verifyme_utility = require("verifyme_utility");

var _config = require("./config");

var _config2 = _interopRequireDefault(_config);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var rsa = _config2.default.keys.rsa;
var ecc = _config2.default.keys.ecc;function mergePrivateKeyIntoKeyManager(key_manager, private_key_string) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManager(key_manager));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(private_key_string));

  return new Promise(function (resolve, reject) {

    key_manager.merge_pgp_private({
      armored: private_key_string
    }, function (err) {
      if (err) reject(err);else resolve(key_manager);
    });
  });
}

/**
 * Unlocks a a password secured private key.
 *
 * @param {KeyManager} key_manager
 *    The {KeyManager} that contains the locked key.
 * @param {string} passphrase
 *    The password to unlock the key.
 * @returns {Promise.<*>}
 *    The promise that the key is unlocked.
 */
function unlockPrivateKeyInKeyManager(key_manager, passphrase) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManager(key_manager));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(passphrase));

  return new Promise(function (resolve, reject) {

    key_manager.unlock_pgp({ passphrase: passphrase }, function (err) {
      if (err) reject(err);else resolve(key_manager);
    });
  });
}

var rsa_promise = loadKey(rsa.public_key, rsa.private_key, rsa.passphrase);
var ecc_promise = loadKey(ecc.public_key, ecc.private_key, ecc.passphrase);

var ecc_key = null;
var rsa_key = null;

var keys_api = {
  rsa_key: rsa_key,
  rsa_promise: rsa_promise,
  ecc_key: ecc_key,
  ecc_promise: ecc_promise
};

exports.default = keys_api;