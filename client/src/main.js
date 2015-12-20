"use strict";

var blinding = require("./blinding");
var client = require("./client");
var pgp = require("./pgp");
var util = require("./util");

/// TODO
function requestPseudonym()
{
  var blind_signature_request = client.prepareBlindSignatureRequest();
  var blind_signature = blind_signature_request.packet;
  var blinding_context = blind_signature_request.context;

  return util.generateBlindingFactor(blinding_context.modulus.bitLength())
    .then(function(blinding_factor) {
      blinding_context.blinding_factor = blind_signature_request.token.data.multiply(blinding_factor);
      return blinding.blind_message(blind_signature.raw_signature, blinding_context).toRadix();
    })
    .then(function (blinded_message) {
      return client.sendBlindingRequest(blinded_message, blinding_context);
    })
    .then(function (signed_blinded_message) {

      var message = new util.BigInteger(signed_blinded_message, 10);
      var unblinded_message = blinding.unblind_message(message, blinding_context);
      blind_signature.sig = unblinded_message.to_mpi_buffer();

      return pgp.export_key_with_signature(blind_signature.target_key, blind_signature);
    })
    .then(function(key_ascii) { console.log(key_ascii); })
    .catch(function(error) { console.log(error); });
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}
