"use strict";
import ECCBlindingContext from "./types/ecc_blinding_context"
import RSABlindingContext from "./types/rsa_blinding_context"
import * as util from "./util"
const assert = util.assert;

module.exports = {

  /// TODO
  blind_message: function(message, blinding_context)
  {
    let blinding_function = null;

    if (RSABlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.blind_rsa_message;
    } else if (ECCBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.blind_ecc_message;
    }

    assert(util.isBigInteger(message));
    assert(null !== blinding_function);
    return blinding_function(message, blinding_context);
  },

  /// TODO
  blind_rsa_message: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(RSABlindingContext.isValidBlindingContext(blinding_context));

    const r = blinding_context.blinding_factor;
    const e = blinding_context.public_exponent;
    const N = blinding_context.modulus;

    return message.multiply(r.modPow(e, N));
  },

  /// TODO
  blind_ecc_message: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(ECCBlindingContext.isValidBlindingContext(blinding_context));

    return null;
  },

  /// TODO
  unblind_message: function(message, blinding_context)
  {
    let blinding_function = null;

    if (RSABlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.unblind_rsa_message;
    } else if (ECCBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.unblind_ecc_message;
    }

    assert(util.isBigInteger(message));
    assert(null !== blinding_function);
    return blinding_function(message, blinding_context);
  },

  /// TODO
  unblind_rsa_message: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(RSABlindingContext.isValidBlindingContext(blinding_context));

    const N = blinding_context.modulus;
    const r = blinding_context.blinding_factor;

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  },

  /// TODO
  unblind_ecc_message: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(ECCBlindingContext.isValidBlindingContext(blinding_context));

    return null;
  }
};