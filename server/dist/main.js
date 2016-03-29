"use strict";

require("babel-polyfill");

var _bodyParser = require("body-parser");

var _bodyParser2 = _interopRequireDefault(_bodyParser);

var _express = require("express");

var _express2 = _interopRequireDefault(_express);

var _config = require("./config");

var _config2 = _interopRequireDefault(_config);

var _keys = require("./keys");

var _keys2 = _interopRequireDefault(_keys);

var _engine = require("./engine");

var _engine2 = _interopRequireDefault(_engine);

var _routes = require("./routes");

var _routes2 = _interopRequireDefault(_routes);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var app = (0, _express2.default)();

// Allow static css and js files
app.use("/css", _express2.default.static(_config2.default.client.base_dir + "/css"));
app.use("/js", _express2.default.static(_config2.default.client.base_dir + "/dist"));

// to support JSON-encoded bodies
app.use(_bodyParser2.default.json());

// Set custom view engine
app.set("views", _config2.default.client.base_dir + "/views");
app.set("view engine", "html");
app.engine("html", _engine2.default);

// Wait with route setup until all keys are loaded.
Promise.all([_keys2.default.rsa_promise, _keys2.default.ecc_promise]).then(function (values) {

  _keys2.default.rsa_key = values[0];
  _keys2.default.ecc_key = values[1];

  app.get("/rsa", _routes2.default.rsa.renderIndex);
  app.post("/rsa", _routes2.default.rsa.signBlindedMessage);

  app.get("/ecdsa/andreev", _routes2.default.ecdsa.andreev.renderIndex);
  app.post("/ecdsa/andreev/init", _routes2.default.ecdsa.andreev.initBlindingAlgorithm);
  app.post("/ecdsa/andreev/sign", _routes2.default.ecdsa.andreev.signBlindedMessage);

  app.get("/ecdsa/butun", _routes2.default.ecdsa.butun.renderIndex);
  app.post("/ecdsa/butun/init", _routes2.default.ecdsa.butun.initBlindingAlgorithm);
  app.post("/ecdsa/butun/sign", _routes2.default.ecdsa.butun.signBlindedMessage);
}).catch(function (error) {
  console.log("");
  console.error("> Error: Server could not load keys.");
  console.error("> Reason: " + error);
  console.error("> Reason: " + error.stack);
  console.log("");
});

/// Run Server
var server = app.listen(8888, function () {
  console.log("");
  console.log("> Start Express Server");
  console.log("> Listening on port %d", server.address().port);
  console.log("");
});