"use strict";

import keys from "../keys"
import Signer from "./signing_ecdsa"

let secret_scalar = {};

/// TODO
function render_key(request, response)
{
  response.render("index", {public_key: keys.ecc_key.armored_pgp_public})
}

/// TODO
async function init_blinding(request, response)
{
  let json = {};
  if (request.body.hasOwnProperty("hashed_token")) {

    const { k, Ŕ } = await Signer.prepare(keys.ecc_key);
    secret_scalar[request.body.hashed_token] = k;

    json.x = Ŕ.affineX.toRadix(32);
    json.y = Ŕ.affineY.toRadix(32);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json)
}

/// TODO
function sign_blinded_message(request, response)
{
  let json = {};
  if (request.body.hasOwnProperty("hashed_token")) {

    const k = secret_scalar[request.body.hashed_token];
    const ḿ = request.body.message;

    json.signed_blinded_message = Signer.sign(ḿ, k, keys.ecc_key);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

const routes_ecdsa_api = {
  render_key,
  init_blinding,
  sign_blinded_message
};

export default routes_ecdsa_api;