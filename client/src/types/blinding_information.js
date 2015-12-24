"use strict";

import * as util from "../util"

/**
 * A rsa blinding context.
 */
export default class BlindingInformation
{
  constructor()
  {
    /** @type {BigInteger|null} */
    this.blinding_factor = null;
    /** @type {BigInteger|null} */
    this.hashed_token = null;
    /** @type {BigInteger|null} */
    this.modulus = null;
    /** @type {BigInteger|null} */
    this.public_exponent = null;
  }

  /// TODO
  containsPublicBlindingInformation()
  {
    return util.isBigInteger(this.modulus)
        && util.isBigInteger(this.public_exponent);
  }

  /// TODO
  containsAllBlindingInformation()
  {
    return this.containsPublicBlindingInformation()
        && util.isBigInteger(this.blinding_factor)
        && util.isBigInteger(this.hashed_token);
  }

  /// TODO
  fromKey(key)
  {
    if (!util.isOpenPGPKey(key)) {
      return false;
    }

    const public_key_package = key.get_primary_keypair().pub;
    this.modulus = public_key_package.n;
    this.public_exponent = public_key_package.e;

    return true;
  }

  /// TODO
  static isValidFullBlindingInformation(blinding_information)
  {
    return (blinding_information instanceof BlindingInformation)
        && blinding_information.containsAllBlindingInformation();
  }

  /// TODO
  static isValidPublicBlindingInformation(blinding_information)
  {
    return (blinding_information instanceof BlindingInformation)
        && blinding_information.containsPublicBlindingInformation();
  }
}
