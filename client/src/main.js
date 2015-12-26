"use strict";

import "babel-polyfill"

import * as blinding from "./blinding"
import * as client from "./client"
import * as pgp from "./pgp"
import * as util from "./util"

/// TODO: think about function extraction
async function requestPseudonym()
{
  // prepare
  const {context, packet, token} = client.prepareBlindSignatureRequest();

  // blind
  const blinding_factor = await util.generateBlindingFactor(context.modulus.bitLength());
  context.blinding_factor = token.multiply(blinding_factor);
  const blinded_message = blinding.blind_message(packet.raw_signature, context).toRadix();

  // sign
  const signed_blinded_message = await client.sendBlindingRequest(blinded_message, context);

  // unblind
  const message = new util.BigInteger(signed_blinded_message, 10);
  const unblinded_message = blinding.unblind_message(message, context);
  packet.sig = unblinded_message.to_mpi_buffer();

  // finish
  const key_ascii = await pgp.export_key_with_signature(packet.target_key, packet);
  console.log(key_ascii);
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}
