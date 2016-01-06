"use strict";

import "babel-polyfill"

import bodyParser from 'body-parser';
import express from "express";
import fs from "fs";
import http from "http";

import config from "./config"
import keys from "./keys";
import * as signing from "./signing";

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

    const rsa_key = values[0];
    const ecc_key = values[1];

    app.get("(/|/rsa)", (request, response) => {
      response.render("index", {public_key: rsa_key.armored_pgp_public})
    });

    app.get("/ecdsa", async (request, response) => {
      response.render("index", {public_key: ecc_key.armored_pgp_public})
    });

    app.post("(/|/rsa)", (request, response) => {
      const signed_blinded_message = signing.sign_blinded_rsa_message(request.body.message, rsa_key);
      response.send(signed_blinded_message);
    });

    app.post("/ecdsa", (request, response) => {
      const signed_blinded_message = signing.sign_blinded_ecdsa_message(request.body.message, ecc_key);
      response.send(signed_blinded_message);
    });
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