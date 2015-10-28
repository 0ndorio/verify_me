"use strict";

var blinding = require("./blinding");
var client = require("./client");
var util = require("./util");

document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;

/// TODO
function requestPseudonym()
{
  var blinding_information = client.collectPublicBlindingInformation();

  util.generatePrimeNumber(1024).then(function(prime) {

    var token = client.getToken();
    blinding_information.blinding_factor = token.data.multiply(prime);
    blinding_information.hashed_token = util.bytes2hex(util.hashMessage(token.data.toRadix()));

    var public_key_string = client.getPublicKeyString();
    var hashed_message = util.hashMessage(public_key_string);

    return blinding.blind_message(hashed_message, blinding_information);
  })
  .then(function(blinded_message) {

    return serverRequest(blinded_message, blinding_information);
  })
}

/// Dummy for a synchronous xmlhttprequest
function serverRequest(blinded_message, blinding_information)
{
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {

    if (xhttp.readyState === 4 && xhttp.status === 200) {

       var message = xhttp.responseText;
       var unblinded_message = blinding.unblind_message(message, blinding_information);
       checkResult(unblinded_message, blinding_information);
     }
  };

  xhttp.open("POST", "/");
  xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
  xhttp.send(JSON.stringify({
    message: blinded_message.toRadix(),
    token_hash: blinding_information.hashed_token
  }));
}

function checkResult(unblinded_message, blinding_information) {

  console.log('Signed Message:');
  console.log('---------------');
  console.log(util.bigInt2ByteString(unblinded_message)+'\n\n');

  var e = blinding_information.public_exponent;
  var N = blinding_information.modulus;
  var m = unblinded_message.modPow(e, N);

  console.log('Original Message:');
  console.log('-----------------');
  console.log(util.bigInt2ByteString(m));
}