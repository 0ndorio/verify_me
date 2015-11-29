"use strict";

var BlindingInformation = require("./types/blinding_information");
var blinding = require("./blinding");
var client = require("./client");
var util = require("./util");

var openpgp = require("openpgp");

function checkResult(unblinded_message, blinding_information)
{
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

function serverRequest(blinded_message, blinding_information)
{
  if (!util.isString(blinded_message)) {
    return Promise.reject("blinded_message is not type of string but '" + typeof blinded_message + "'");
  }

  if(!(blinding_information instanceof BlindingInformation && util.isBigInteger(blinding_information.hashed_token))) {
    return Promise.reject("no hashed token stored in blinding_information");
  }

  return new Promise(function(resolve, reject) {

    var xhttp = new XMLHttpRequest();
    xhttp.open("POST", "/");
    xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");

    xhttp.onload = function () {
      if (xhttp.readyState === 4 && xhttp.status === 200) {
        resolve(xhttp.responseText);
      } else {
        reject(new Error(xhttp.statusText));
      }
    };

    xhttp.onerror = function(error) {
      reject(new Error("error handler called with: " + error));
    };

    xhttp.send(JSON.stringify({
      message: blinded_message,
      token_hash: blinding_information.hashed_token.toString(16)
    }));
  });
}

/// TODO
function requestPseudonym()
{
  var blind_signature = blinding.prepareBlindSignature();
  var token = client.getToken();

  /// blinding factor and modulus must be coprime
  ///   - ensured through the use of prime numbers
  ///   - blinding factor is generated through the multiplication of prime token and two additional prime numbers
  /// blinding factor must be smaller than Modulus
  ///   - number of bits after multiplication of two numbers with the same bit length (n) is 2n or less
  ///     (https://math.stackexchange.com/questions/682618/the-maximum-number-of-digits-in-binary-multiplication)
  ///   - TODO: unsure how to handle this properly
  var blinding_information = client.collectPublicBlindingInformation();
  var prime_bit_length = Math.floor((blinding_information.modulus.bitLength() - token.data.bitLength() - 1) / 2);

  return util.generateTwoPrimeNumbers(prime_bit_length)
    .then(function (primes) {

      blinding_information.hashed_token = util.bytes2MPI(util.hashMessage(token.data.toRadix())).data;
      blinding_information.blinding_factor = token.data.multiply(primes[0].multiply(primes[1]));

      /// TODO: workaround for unhandled length problem ... if blinding factor is to large this reduces its size
      if (blinding_information.blinding_factor.compareTo(blinding_information.modulus) > 0) {
        blinding_information.blinding_factor = token.data.multiply(primes[0]);
      }

      return blinding.blind_message(blind_signature.message, blinding_information).toRadix();
    })
    .then(function (blinded_message) {
      return serverRequest(blinded_message, blinding_information);
    })
    .then(function (signed_blinded_message) {
      var unblinded_message = blinding.unblind_message(signed_blinded_message, blinding_information);
      if (unblinded_message === null) {
        throw new Error("Could not unblind the signed blinded message");
      }

      var signature_packet = blind_signature.signature_packet;
      signature_packet.signature = unblinded_message.toMPI();

      var verify_me = new openpgp.packet.Literal();
      verify_me.setBytes(signature_packet.signature, 'binary');

      var public_key = client.getPublicKey();
      var result = signature_packet.verify(client.getServerPublicKey().primaryKey, {
        key: public_key.primaryKey,
        userid: public_key.getPrimaryUser().user.userId
      });

      console.log("Signature veryfied: " + result);

      /// DUMP
      var public_key = client.getPublicKey();
      var user = public_key.getPrimaryUser().user;

      if (!user.otherCertifications) {
        user.otherCertifications = [];
      }
      user.otherCertifications.push(signature_packet);

      console.log(public_key.armor());
      return public_key.armor();
    });
}

// TODO: refactoring necessary
// set request button active
if (typeof document !== "undefined" && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}

// exports requestPseudonym to allow testing
if(typeof exports !== 'undefined') {
  exports.requestPseudonym = requestPseudonym;
  exports.serverRequest = serverRequest;
}