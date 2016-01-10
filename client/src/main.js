"use strict";

import "babel-polyfill"

import Blinder from "./blinding/blinder"
import blinding_util from "./blinding/blinding_util"
import client from"./client"
import pgp from "./pgp/pgp"

/// TODO: think about function extraction
async function requestPseudonym()
{
  // prepare
  const { blinder, packet } = await blinding_util.prepareBlinding();

  // forge
  await blinder.forgeSignature(packet);

  // finish
  const key_ascii = await pgp.export_key_with_signature(packet.target_key, packet);
  console.log(key_ascii);
}

// set request button active
if (document && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}