"use strict";

import * as util from "../util"

/**
 * A ecc blinding context.
 */
export default class ECCBlindingContext
{
  constructor()
  {
    /** @type {Point|null} */
    this.blinding_factor = null;
    /** @type {Curve|null} */
    this.curve = null;
    /** @type {Point|null} */
    this.public_point = null;
    /** @type {BigInteger|null} */
    this.hashed_token = null;
  }

  /// TODO
  containsPublicBlindingInformation()
  {
    return util.isPoint(this.public_point)
        && util.isCurve(this.curve);
  }

  /// TODO
  containsAllBlindingInformation()
  {
    return this.containsPublicBlindingInformation()
        && util.isBigInteger(this.blinding_factor)
        && utl.isBigInteger(this.hashed_token);
  }

  /// TODO
  encode_signature_data(signData, hasher)
  {
    return util.BigInteger.fromByteArrayUnsigned(signData);
  }

  /// TODO
  static fromKey(key)
  {
    if (!util.isKeyManager(key)) {
      return null;
    }

    const public_key_package = key.get_primary_keypair().pub;

    let context = new ECCBlindingContext();
    context.curve = public_key_package.curve;
    context.public_point = public_key_package.R;

    return context;
  }

  /// TODO
  static isValidFullBlindingInformation(blinding_context)
  {
    return (blinding_context instanceof ECCBlindingContext)
        && blinding_context.containsAllBlindingInformation();
  }

  /// TODO
  static isValidPublicBlindingInformation(blinding_context)
  {
    return (blinding_context instanceof ECCBlindingContext)
        && blinding_context.containsPublicBlindingInformation();
  }
}
