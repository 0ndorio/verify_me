"use strict";

import "babel-polyfill"

import bodyParser from 'body-parser';
import express from "express";

import config from "./config"
import keys from "./keys";
import customHtmlEngine from "./engine"
import routes from "./routes"

let app = express();

// Allow static css and js files
app.use("/css", express.static(config.client.base_dir + "/css"));
app.use("/js", express.static(config.client.base_dir + "/dist"));

// to support JSON-encoded bodies
app.use(bodyParser.json());

// Set custom view engine
app.set("views", config.client.base_dir + "/views");
app.set("view engine", "html");
app.engine("html", customHtmlEngine);

// Wait with route setup until all keys are loaded.
Promise.all([keys.rsa_promise, keys.ecc_promise])
  .then((values) => {

    keys.rsa_key = values[0];
    keys.ecc_key = values[1];

    app.get("/rsa", routes.rsa.renderIndex);
    app.post("/rsa", routes.rsa.signBlindedMessage);

    app.get("/ecdsa", routes.ecdsa.renderIndex);
    app.post("/ecdsa/init", routes.ecdsa.initBlindingAlgorithm);
    app.post("/ecdsa/sign", routes.ecdsa.signBlindedMessage);
  })
  .catch((error) => {
    console.log("");
    console.error("> Error: Server could not load keys.");
    console.error("> Reason: " + error);
    console.error("> Reason: " + error.stack);
    console.log("");
  });

/// Run Server
const server = app.listen(8888, () => {
  console.log("");
  console.log("> Start Express Server");
  console.log("> Listening on port %d", server.address().port);
  console.log("");
});