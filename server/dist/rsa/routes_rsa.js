"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _keys = require("../keys");

var _keys2 = _interopRequireDefault(_keys);

var _signing_rsa = require("./signing_rsa");

var _signing_rsa2 = _interopRequireDefault(_signing_rsa);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Render a RSA key into index html.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function renderIndex(request, response) {
  response.render("index", { public_key: _keys2.default.rsa_key.armored_pgp_public });
};

/**
 * Signs a given RSA blinded message.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function signBlindedMessage(request, response) {
  var json = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    json.signed_blinded_message = (0, _signing_rsa2.default)(request.body.message, _keys2.default.rsa_key);
  } else {

    json.error = "Missing Token...";
  }

  response.send(json);
};

var routes_rsa_api = {
  renderIndex: renderIndex,
  signBlindedMessage: signBlindedMessage
};

exports.default = routes_rsa_api;