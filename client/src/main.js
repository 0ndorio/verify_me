"use strict";

import "babel-polyfill"

import * as blinding from "./blinding"
import * as client from "./client"
import * as pgp from "./pgp"
import * as util from "./util"

/// TODO
async function requestPseudonym()
{
  const blind_signature_request = client.prepareBlindSignatureRequest();
  let blind_signature = blind_signature_request.packet;
  let blinding_context = blind_signature_request.context;

  const blinding_factor = await util.generateBlindingFactor(blinding_context.modulus.bitLength());
  blinding_context.blinding_factor = blind_signature_request.token.multiply(blinding_factor);

  const blinded_message = blinding.blind_message(blind_signature.raw_signature, blinding_context).toRadix();
  const signed_blinded_message = await client.sendBlindingRequest(blinded_message, blinding_context);

  const message = new util.BigInteger(signed_blinded_message, 10);
  const unblinded_message = blinding.unblind_message(message, blinding_context);
  blind_signature.sig = unblinded_message.to_mpi_buffer();

  const key_ascii = await pgp.export_key_with_signature(blind_signature.target_key, blind_signature);
  console.log(key_ascii);

  return key_ascii;
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}
