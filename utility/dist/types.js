"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Point = exports.Tags = exports.KeyManager = exports.Curve = exports.Buffer = exports.BigInteger = undefined;

var _keybaseEcurve = require("keybase-ecurve");

Object.defineProperty(exports, "Point", {
  enumerable: true,
  get: function get() {
    return _keybaseEcurve.Point;
  }
});

var _kbpgp = require("kbpgp");

var kbpgp = _interopRequireWildcard(_kbpgp);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

var BigInteger = exports.BigInteger = kbpgp.bn.BigInteger;
var Buffer = exports.Buffer = kbpgp.Buffer;
var Curve = exports.Curve = kbpgp.ecc.curves.Curve;
var KeyManager = exports.KeyManager = kbpgp.KeyManager;
var Tags = exports.Tags = {
  public_key_algorithms: kbpgp.const.openpgp.public_key_algorithms,
  verification_algorithms: kbpgp.const.openpgp.verification_algorithms
};