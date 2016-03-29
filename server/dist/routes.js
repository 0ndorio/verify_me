"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _routes = require("./ecdsa_andreev/routes");

var _routes2 = _interopRequireDefault(_routes);

var _routes3 = require("./ecdsa_butun/routes");

var _routes4 = _interopRequireDefault(_routes3);

var _routes_rsa = require("./rsa/routes_rsa");

var _routes_rsa2 = _interopRequireDefault(_routes_rsa);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var routes_api = {
  ecdsa: {
    andreev: _routes2.default,
    butun: _routes4.default
  },
  rsa: _routes_rsa2.default
};

exports.default = routes_api;