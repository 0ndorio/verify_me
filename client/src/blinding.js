"use strict";

import BlindingInformation from "./types/blinding_information"
import * as util from "./util"

module.exports = {

  /// TODO : Avoid blinding and encrpytion in one step!
  blind_message: function(message, blinding_information)
  {
    if (!util.isBigInteger(message)
        || !BlindingInformation.isValidFullBlindingInformation(blinding_information)) {
      return null;
    }

    const r = blinding_information.blinding_factor;
    const e = blinding_information.public_exponent;
    const N = blinding_information.modulus;

    return message.multiply(r.modPow(e, N));
  },

  /// TODO
  unblind_message: function(message, blinding_information)
  {
    if (!util.isBigInteger(message)
        || !BlindingInformation.isValidFullBlindingInformation(blinding_information)) {
      return null;
    }

    const N = blinding_information.modulus;
    const r = blinding_information.blinding_factor;

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  }
};