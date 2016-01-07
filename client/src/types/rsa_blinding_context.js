"use strict";

import * as pad from "../../node_modules/kbpgp/lib/pad"
import * as util from "../util"

/**
 * A rsa blinding context.
 */
export default class RSABlindingContext
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
  encode_signature_data(data, hasher)
  {
    const hashed_data = hasher(data);
    const target_length = this.modulus.mpi_byte_length();

    return pad.emsa_pkcs1_encode(hashed_data, target_length, { hasher: hasher });
  }

  /// TODO
  static fromKey(key)
  {
    if (!util.isKeyManager(key)) {
      return null;
    }

    const public_key_package = key.get_primary_keypair().pub;

    let blinding_context = new RSABlindingContext();
    blinding_context.modulus = public_key_package.n;
    blinding_context.public_exponent = public_key_package.e;

    return blinding_context;
  }

  /// TODO
  static isValidFullBlindingInformation(blinding_context)
  {
    return (blinding_context instanceof RSABlindingContext)
        && blinding_context.containsAllBlindingInformation();
  }

  /// TODO
  static isValidPublicBlindingInformation(blinding_context)
  {
    return (blinding_context instanceof RSABlindingContext)
        && blinding_context.containsPublicBlindingInformation();
  }
}
