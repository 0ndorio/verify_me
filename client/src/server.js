"use strict";

import BlindingContext from "./blinding/blinding_context"

import util from "./util"
const assert = util.assert;

export function sendRequest(json_string, path = "/", method = "POST")
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

export async function sendBlindingRequest(blinded_message, blinding_context)
{
  assert(util.isBigInteger(blinded_message));
  assert((blinding_context instanceof BlindingContext) && blinding_context.hasOwnProperty("hashed_token"));

  const message = JSON.stringify({
    message:    blinded_message.toRadix(16),
    token_hash: blinding_context.hashed_token.toRadix(16)
  });

  return sendRequest(message)
    .then(request_result => {
      return new util.BigInteger(request_result, 16);
    });
}
