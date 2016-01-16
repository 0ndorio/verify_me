"use strict";

import BlindingContext from "./blinding/blinding_context"
import util, { assert }from "./util"

/**
 * Sends a async XMLHttpRequest to the server.
 *
 * @param {string} json_string
 *    The message we send to the server.
 * @param {string} path
 *    The path we try to access.
 * @param {string} method
 *    The http method we want to use.
 * @returns {Promise.<string|Error>}
 *    The promise of a server result.
 */
function sendRequest(json_string, path = "/", method = "POST")
{
  assert(util.isString(json_string));
  assert(util.isString(path));
  assert(util.isString(method));

  return new Promise((resolve, reject) => {

    let xhttp = new XMLHttpRequest();
    xhttp.open(method, path);
    xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");

    xhttp.onload = () => {

      if (xhttp.readyState === 4 && xhttp.status === 200) {
        resolve(xhttp.responseText);
      } else {
        reject(new Error(xhttp.statusText));
      }
    };

    xhttp.onerror = (error) => { reject(new Error("error handler called with: " + error)) };

    xhttp.send(json_string);
  });
}

/**
 * Sends the request for a RSA based signature.
 *
 * @param {BigInteger} blinded_message
 *    The message to be signed.
 * @param {BlindingContext} blinding_context
 *    The blinding context we use to authenticate our request.
 * @returns {Promise.<string|Error>}
 *    The promise of a RSA signed message.
 */
async function requestRsaBlinding(blinded_message, blinding_context)
{
  assert(util.isBigInteger(blinded_message));
  assert((blinding_context instanceof BlindingContext)
         && blinding_context.hasOwnProperty("hashed_token"));

  const message = JSON.stringify({
    message:    blinded_message.toRadix(32),
    hashed_token: blinding_context.hashed_token.toRadix(32)
  });

  return sendRequest(message, "/rsa")
    .then(response => {
      assert(util.isString(response));

      const request_result = JSON.parse(response);
      return new util.BigInteger(request_result.signed_blinded_message, 32);
    });
}

/**
 * Sends the request for a ECDSA based signature.
 *
 * @param {BigInteger} blinded_message
 *    The message to be signed.
 * @param {BlindingContext} blinding_context
 *    The blinding context we use to authenticate our request.
 * @returns {Promise.<string|Error>}
 *    The promise of an ECDSA signed message.
 */
async function requestEcdsaBlinding(blinded_message, blinding_context)
{
  assert(util.isBigInteger(blinded_message));
  assert((blinding_context instanceof BlindingContext)
        && blinding_context.hasOwnProperty("hashed_token"));

  const message = JSON.stringify({
    message: blinded_message.toRadix(32),
    hashed_token: blinding_context.hashed_token.toRadix(32)
  });

  return sendRequest(message, "/ecdsa/sign")
    .then(response => {
      assert(util.isString(response));

      const request_result = JSON.parse(response);
      return new util.BigInteger(request_result.signed_blinded_message, 32)
    });
}

/**
 * Sends the request to initialize the ECDSA based blinding process.
 *
 * @param {BlindingContext} blinding_context
 *    The blinding context we use to authenticate our request.
 * @returns {Promise.<string|Error>}
 *    The promise of public information necessary for the
 *    ECDSA blinding algorithm.
 */
async function requestEcdsaBlindingInitialization(blinding_context)
{
  assert((blinding_context instanceof BlindingContext)
        && blinding_context.hasOwnProperty("hashed_token"));

  const message = JSON.stringify({
    hashed_token: blinding_context.hashed_token.toRadix(32)
  });

  return sendRequest(message, "/ecdsa/init")
    .then(response => {
      assert(util.isString(response));

      const request_result = JSON.parse(response);
      const P = blinding_context.curve.mkpoint({
        x: new util.BigInteger(request_result.px, 32),
        y: new util.BigInteger(request_result.py, 32)
      });

      const Q = blinding_context.curve.mkpoint({
        x: new util.BigInteger(request_result.qx, 32),
        y: new util.BigInteger(request_result.qy, 32)
      });

      return {P, Q};
    });
}

const server_api = {
  sendRequest,
  requestEcdsaBlinding,
  requestEcdsaBlindingInitialization,
  requestRsaBlinding
};

export default server_api;