"use strict";

import "babel-polyfill"

import express from "express";
import fs from "fs";
import http from "http";

import * as keys from "./server_keys";
import * as signing from "./signing";

// Create Express framework
let app = express();

// Allow static css and js files
const base_dir = __dirname + "/../../client";
app.use("/css", express.static(base_dir + "/css"));
app.use("/js", express.static(base_dir + "/dist"));

// Set custom view engine
app.set("views", base_dir + "/views");
app.set("view engine", "html");

app.engine("html", (file_path, options, callback) => {
  fs.readFile(file_path, (err, content) => {
  
    if (err) { return callback(new Error(err)); }

    const rendered = content.toString()
      .replace("{public_key}", options.public_key);

    return callback(null, rendered);
  });
});

// Routes
app.get("(/|/rsa)", (request, response) =>
{
  Promise.race([keys.rsa_public_key])
    .then(key => key.armored_pgp_public)
    .then(ascii_armor => response.render("index", { public_key: ascii_armor }));
});

app.post("(/|/rsa)", (request, response) => {
  signing.sign_blinded_rsa_message();
});

app.get("/ecc", async (request, response) =>
{
  Promise.race([keys.ecc_public_key])
    .then(key => key.armored_pgp_public)
    .then(ascii_armor => response.render("index", { public_key: ascii_armor }));
});

app.post("/ecc", (request, response) => {
  signing.sign_blinded_ecc_mesage();
});

// Start listening on the por
const server = app.listen(8888, () => {
  console.log("Listening on port %d", server.address().port);
});
