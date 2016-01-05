import "babel-polyfill"

import express from "express";
import fs from "fs";
import http from "http";

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
app.get("(/|/rsa)", (request, response) => {
  response.render("rsa", { public_key: "Alice 123"});
});

app.get("/ecc", (request, response) => {
  response.render("ecc", { public_key: "Bob 456"});
});


// Start listening on the por
const server = app.listen(8888, () => {
  console.log("Listening on port %d", server.address().port);
});
