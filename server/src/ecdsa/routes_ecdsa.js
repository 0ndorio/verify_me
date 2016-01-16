"use strict";

import keys from "../keys"
import Signer from "./signing_ecdsa"

let secret_scalar = {};

/**
 * Render an ECC key into index html.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
function renderIndex(request, response)
{
  response.render("index", {public_key: keys.ecc_key.armored_pgp_public})
}

/**
 * Initializes the ECDSA blind signature algorithm.
 *
 * @param {IncomingMessage} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {ServerResponse} response
 *    HTTP server response
 */
async function initBlindingAlgorithm(request, response)
{
  console.log(request.constructor.name);
  console.log(response.constructor.name);

  let json = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    const { p, P, q, Q } = await Signer.prepare(keys.ecc_key);

    secret_scalar[request.body.hashed_token] = {p, q};

    json.px = P.affineX.toRadix(32);
    json.py = P.affineY.toRadix(32);
    json.qx = Q.affineX.toRadix(32);
    json.qy = Q.affineY.toRadix(32);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json)
}

/**
 * Signs a a given ECDSA blinded message.
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

    const secret_scalars = secret_scalar[request.body.hashed_token];
    const blinded_message = request.body.message;

    json.signed_blinded_message = Signer.sign(blinded_message, secret_scalars, keys.ecc_key);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

const routes_ecdsa_api = {
  renderIndex,
  initBlindingAlgorithm,
  signBlindedMessage
};

export default routes_ecdsa_api;