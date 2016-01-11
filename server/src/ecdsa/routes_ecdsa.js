"use strict";

import keys from "../keys"
import signing from "./signing_ecdsa"

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

    const { k, R } = await signing.prepare_blinding(keys.ecc_key);
    secret_scalar[request.body.hashed_token] = k;

    json.x = R.affineX.toRadix(32);
    json.y = R.affineY.toRadix(32);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json)
}

/// TODO
function sign_blinded_message(request, response)
{
  const signed_blinded_message = signing.sign_blinded_ecdsa_message(request.body.message, keys.ecc_key);
  response.send(signed_blinded_message);
}

const routes_ecdsa_api = {
  render_key,
  init_blinding,
  sign_blinded_message
};

export default routes_ecdsa_api;