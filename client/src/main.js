"use strict";

import * as blinding from "./blinding"
import * as client from "./client"
import * as pgp from "./pgp"
import * as util from "./util"

/// TODO
function requestPseudonym()
{
  const blind_signature_request = client.prepareBlindSignatureRequest();
  let blind_signature = blind_signature_request.packet;
  let blinding_context = blind_signature_request.context;

  return util
    .generateBlindingFactor(blinding_context.modulus.bitLength())
    .then((blinding_factor) => {

      blinding_context.blinding_factor = blind_signature_request.token.multiply(blinding_factor);
      return blinding.blind_message(blind_signature.raw_signature, blinding_context).toRadix();
    })
    .then((blinded_message) => client.sendBlindingRequest(blinded_message, blinding_context))
    .then((signed_blinded_message) => {

      const message = new util.BigInteger(signed_blinded_message, 10);
      const unblinded_message = blinding.unblind_message(message, blinding_context);
      blind_signature.sig = unblinded_message.to_mpi_buffer();

      return pgp.export_key_with_signature(blind_signature.target_key, blind_signature);
    })
    .then((key_ascii) => console.log(key_ascii))
    .catch((error) => console.log(error));
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}
