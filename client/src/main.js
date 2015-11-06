"use strict";

var blinding = require("./blinding");
var client = require("./client");
var util = require("./util");

function checkResult(unblinded_message, blinding_information) {

  console.log('Signed Message:');
  console.log('---------------');
  console.log(util.bigInt2Bytes(unblinded_message)+'\n\n');

  var e = blinding_information.public_exponent;
  var N = blinding_information.modulus;
  var m = unblinded_message.modPow(e, N);

  console.log('Original Message:');
  console.log('-----------------');
  console.log(util.bigInt2Bytes(m));
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

/// TODO
function requestPseudonym()
{
  var blinding_information = client.collectPublicBlindingInformation();

  /// blinding factor and modulus must be coprime
  ///   - ensured through the use of prime numbers
  ///   - blinding factor is generated through the multiplication of prime token and two additional prime numbers
  /// blinding factor must be smaller than Modulus
  ///   - number of bits after multiplication of two numbers with the same bit length (n) is 2n or less
  ///     (https://math.stackexchange.com/questions/682618/the-maximum-number-of-digits-in-binary-multiplication)
  ///   - TODO: unsure how to handle this properly
  var prime_bit_length = Math.floor(blinding_information.modulus.bitLength / 4);

  util.generateTwoPrimeNumbers(prime_bit_length).then(function(primes) {

    var public_key_string = client.getPublicKeyString();
    var hashed_message = util.hashMessage(public_key_string);

    var token = client.getToken().byteLength();

    blinding_information.blinding_factor = token.data.multiply(primes[0].multiply(primes[1]));

    /// TODO: workaround for unhandled length problem ... if blinding factor is to large this reduces its size
    if (blinding_information.blinding_factor.compareTo(blinding_information.modulus) > 0) {
      blinding_information.blinding_factor = token.data.multiply(primes[0]);
    }

    blinding_information.hashed_token = util.bytes2hex(util.hashMessage(token.data.toRadix()));

    return blinding.blind_message(hashed_message, blinding_information);
  })
  .then(function(blinded_message) {
    return serverRequest(blinded_message, blinding_information);
  });
}

document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;