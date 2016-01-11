"use strict";

import keys from "../keys"
import sign from "./signing_rsa"

/// TODO
function render_key(request, response)
{
  response.render("index", {public_key: keys.rsa_key.armored_pgp_public})
};

/// TODO
function sign_blinded_message(request, response)
{
  let json = {};
  if (request.body.hasOwnProperty("hashed_token")) {
    json.signed_blinded_message = sign(request.body.message, keys.rsa_key);
  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
};

const routes_rsa_api = {
  render_key,
  sign_blinded_message
};

export default routes_rsa_api;

