"use strict";

import RSABlindingContext from "./types/rsa_blinding_context"
import * as util from "./util"

module.exports = {

  /// TODO : Avoid blinding and encrpytion in one step!
  blind_message: function(message, blinding_context)
  {
    if (!util.isBigInteger(message)
        || !RSABlindingContext.isValidFullBlindingInformation(blinding_context)) {
      return null;
    }

    const r = blinding_context.blinding_factor;
    const e = blinding_context.public_exponent;
    const N = blinding_context.modulus;

    return message.multiply(r.modPow(e, N));
  },

  /// TODO
  unblind_message: function(message, blinding_context)
  {
    if (!util.isBigInteger(message)
        || !RSABlindingContext.isValidFullBlindingInformation(blinding_context)) {
      return null;
    }

    const N = blinding_context.modulus;
    const r = blinding_context.blinding_factor;

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  }
};