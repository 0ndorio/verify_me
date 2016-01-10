"use strict";

import "babel-polyfill"

import blinding_util from "./blinding/blinding_util"
import { sendBlindingRequest } from "./server"
import client from"./client"
import pgp from "./pgp/pgp"

/// TODO: think about function extraction
async function requestPseudonym()
{
  // prepare
  const { blinder, packet } = await blinding_util.prepareBlinding();

  // blind
  const blinded_message = blinder.blind(packet.raw_signature);

  // request sign from server
  const signed_blinded_message = await sendBlindingRequest(blinded_message, blinder.context);

  // unblind
  const unblinded_message = blinder.unblind(signed_blinded_message);
  packet.sig = unblinded_message.to_mpi_buffer();

  // finish
  const key_ascii = await pgp.export_key_with_signature(packet.target_key, packet);
  console.log(key_ascii);
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}
