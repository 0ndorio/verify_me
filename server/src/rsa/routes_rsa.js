"use strict";

import keys from "../keys"
import sign from "./signing_rsa"

/**
 * Render a RSA key into index html.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function renderIndex(request, response)
{
  response.render("index", {public_key: keys.rsa_key.armored_pgp_public})
};

/**
 * Signs a given RSA blinded message.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function signBlindedMessage(request, response)
{
  let json = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    json.signed_blinded_message = sign(request.body.message, keys.rsa_key);

  } else {

    json.error = "Missing Token...";
  }

  response.send(json);
};

const routes_rsa_api = {
  renderIndex,
  signBlindedMessage
};

export default routes_rsa_api;

