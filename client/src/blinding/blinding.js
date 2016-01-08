"use strict";
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import RsaBlindingContext from "./blinding_context_rsa"
import * as util from "./../util"
const assert = util.assert;

module.exports = {

  /// TODO
  blind_message: function(message, blinding_context)
  {
    let blinding_function = null;

    if (RsaBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.blind_message_rsa;
    } else if (EcdsaBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.blind_message_ecdsa;
    }

    assert(util.isBigInteger(message));
    assert(null !== blinding_function);
    return blinding_function(message, blinding_context);
  },

  /// TODO
  blind_message_rsa: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(blinding_context));

    const r = blinding_context.blinding_factor;
    const e = blinding_context.public_exponent;
    const N = blinding_context.modulus;

    return message.multiply(r.modPow(e, N));
  },

  /// TODO
  blind_message_ecdsa: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(blinding_context));

    return null;
  },

  /// TODO
  unblind_message: function(message, blinding_context)
  {
    let blinding_function = null;

    if (RsaBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.unblind_message_rsa;
    } else if (EcdsaBlindingContext.isValidBlindingContext(blinding_context)) {
      blinding_function = this.unblind_message_ecdsa;
    }

    assert(util.isBigInteger(message));
    assert(null !== blinding_function);
    return blinding_function(message, blinding_context);
  },

  /// TODO
  unblind_message_rsa: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(blinding_context));

    const N = blinding_context.modulus;
    const r = blinding_context.blinding_factor;

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  },

  /// TODO
  unblind_message_ecdsa: function(message, blinding_context)
  {
    assert(util.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(blinding_context));

    return null;
  }
};