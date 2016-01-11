"use strict";

import "babel-polyfill"

import bodyParser from 'body-parser';
import express from "express";
import fs from "fs";
import http from "http";

import config from "./config"
import keys from "./keys";
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
app.engine("html", (file_path, options, callback) => {
  fs.readFile(file_path, (err, content) => {

    if (err) {
      return callback(new Error(err));
    }

    const rendered = content.toString()
      .replace("{public_key}", options.public_key);

    return callback(null, rendered);
  });
});

// Wait with rout setup until all keys are loaded.
Promise.all([keys.rsa_promise, keys.ecc_promise])
  .then((values) => {

    keys.rsa_key = values[0];
    keys.ecc_key = values[1];

    app.route("/rsa")
       .get(routes.rsa.render_key)
       .post(routes.rsa.sign_blinded_message);

    app.get("/ecdsa", routes.ecdsa.render_key);
    app.post("/ecdsa/init", routes.ecdsa.init_blinding);
    app.post("/ecdsa/sign", routes.ecdsa.sign_blinded_message);

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