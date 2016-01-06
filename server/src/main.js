"use strict";

import "babel-polyfill"

import express from "express";
import fs from "fs";
import http from "http";

import config from "./config"
import keys from "./keys";
import * as signing from "./signing";

let app = express();

Promise.all([keys.rsa_promise, keys.ecc_promise])
  .then((values) => {

    const rsa_key = values[0];
    const ecc_key = values[1];

    // Allow static css and js files
    app.use("/css", express.static(config.client.base_dir + "/css"));
    app.use("/js", express.static(config.client.base_dir + "/dist"));

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

    // RSA Routes
    app.get("(/|/rsa)", (request, response) => {
      response.render("index", {public_key: rsa_key.armored_pgp_public})
    });

    app.post("(/|/rsa)", (request, response) => {
      signing
        .sign_blinded_rsa_message(null)
        .then(signed_blinded_message => response.send(signed_blinded_message));
    });

    // ECDSA Routes
    app.get("/ecdsa", async (request, response) => {
      response.render("index", {public_key: ecc_key.armored_pgp_public})
    });

    app.post("/ecdsa", (request, response) => {
      signing
        .sign_blinded_ecdsa_mesage(null)
        .then(signed_blinded_message => response.send(signed_blinded_message));
    });

    const server = app.listen(8888, () => {
      console.log("");
      console.log("> Start Express Server");
      console.log("> Listening on port %d", server.address().port);
      console.log("");
    });
  })
  .catch((error) => {
    console.log("");
    console.error("> Error: Server could not load keys.");
    console.error("> Reason: " + error);
    console.error("> Reason: " + error.stack);
    console.log("");
  });