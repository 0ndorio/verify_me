"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = sign;

var _verifyme_utility = require("verifyme_utility");

/**
 * Signs the given blinded message.
 *
 * @param {string} message
 *    The message to sign.
 * @param {KeyManager} key_manager
 *    The {KeyManager} containing the ecc based key
 *    that will be used to sign the message.
 * @returns {string}
 *    The signed message.
 */
function sign(message, key_manager) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(message));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isKeyManagerForRsaSign(key_manager));

  var key_pair = key_manager.get_primary_keypair();

  var m = new _verifyme_utility.BigInteger(message, 32);
  var n = key_pair.pub.n;
  var d = key_pair.priv.d;

  return m.modPow(d, n).toRadix(32);
}