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

    var r = blinding_information.blinding_factor;
    var e = blinding_information.public_exponent;
    var N = blinding_information.modulus;

    return message.multiply(r.modPow(e, N));
  },

  /// TODO
  unblind_message: function(message, blinding_information)
  {
    if (!util.isBigInteger(message)
        || !BlindingInformation.isValidFullBlindingInformation(blinding_information)) {
      return null;
    }

    var N = blinding_information.modulus;
    var r = blinding_information.blinding_factor;

    var r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  }
};