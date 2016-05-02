"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});


/**
 * Initializes the ECDSA blind signature algorithm.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */

var initBlindingAlgorithm = function () {
  var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(request, response) {
    var json, _ref, k, Ŕ;

    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            json = {};

            if (!(request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token"))) {
              _context.next = 12;
              break;
            }

            _context.next = 4;
            return _signing2.default.prepare(_keys2.default.ecc_key);

          case 4:
            _ref = _context.sent;
            k = _ref.k;
            Ŕ = _ref.Ŕ;


            secret_scalar[request.body.hashed_token] = k;

            json.Ŕx = Ŕ.affineX.toRadix(32);
            json.Ŕy = Ŕ.affineY.toRadix(32);

            _context.next = 13;
            break;

          case 12:
            json.error = "Missing Token...";

          case 13:

            response.send(json);

          case 14:
          case "end":
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function initBlindingAlgorithm(_x, _x2) {
    return ref.apply(this, arguments);
  };
}();

/**
 * Signs a a given ECDSA blinded message.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */


var _keys = require("../keys");

var _keys2 = _interopRequireDefault(_keys);

var _signing = require("./signing");

var _signing2 = _interopRequireDefault(_signing);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var secret_scalar = {};

/**
 * Render an ECC key into index html.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function renderIndex(request, response) {
  response.render("index", { public_key: _keys2.default.ecc_key.armored_pgp_public });
}function signBlindedMessage(request, response) {
  var json = {};
  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    var request_scalar = secret_scalar[request.body.hashed_token];
    var blinded_message = request.body.message;

    json.signed_blinded_message = _signing2.default.sign(blinded_message, request_scalar, _keys2.default.ecc_key);
  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

var routes_ecdsa_api = {
  renderIndex: renderIndex,
  initBlindingAlgorithm: initBlindingAlgorithm,
  signBlindedMessage: signBlindedMessage
};

exports.default = routes_ecdsa_api;