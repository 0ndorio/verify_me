"use strict";

import BlindingContext from "./blinding/blinding_context"
import util, { assert }from "./util"

/// TODO
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

/// TODO
async function requestRsaBlinding(blinded_message, blinding_context)
{
  assert(util.isBigInteger(blinded_message));
  assert((blinding_context instanceof BlindingContext) && blinding_context.hasOwnProperty("hashed_token"));

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

/// TODO
async function requestEcdsaBlindingInitialization(blinding_context)
{
  assert((blinding_context instanceof BlindingContext) && blinding_context.hasOwnProperty("hashed_token"));

  const message= JSON.stringify({
    hashed_token: blinding_context.hashed_token.toRadix(32)
  });

  return sendRequest(message, "/ecdsa/init")
    .then(response => {
      assert(util.isString(response));

      const request_result = JSON.parse(response);
      return blinding_context.curve.mkpoint({
        x: new util.BigInteger(request_result.x, 32),
        y: new util.BigInteger(request_result.y, 32)
      });
    });
}

const server_api = {
  sendRequest,
  requestEcdsaBlindingInitialization,
  requestRsaBlinding
};

export default server_api;