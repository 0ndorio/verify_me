"use strict";

import * as pad from "../../../node_modules/kbpgp/lib/pad"

import BlindingContext from "../blinding_context"
import util, { assert } from "../../util"

/**
 * A rsa based blinding context.
 */
export default class RsaBlindingContext extends BlindingContext
{
  constructor()
  {
    super();
    
    /** @type {BigInteger|null} */
    this.blinding_factor = null;
    /** @type {BigInteger|null} */
    this.modulus = null;
    /** @type {BigInteger|null} */
    this.public_exponent = null;
  }

  /**
   * Checks if a given {object} is a RsaBlindingContext which fulfills all requirements
   * to start the rsa blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the rsa blind signature creation
   *    else {false}
   */
  static isValidBlindingContext(object)
  {
    return (object instanceof RsaBlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the RSA based input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The ECC based public key_manager that belongs to the blind signature issuer.
   * @return {EcdsaBlindingContext}
   *    The generated blinding context.
   */
  static fromKey(key_manager)
  {
    util.assert(util.isKeyManagerForRsaSign(key_manager));

    const public_key_package = key_manager.get_primary_keypair().pub;

    let blinding_context = new RsaBlindingContext();
    blinding_context.modulus = public_key_package.n;
    blinding_context.public_exponent = public_key_package.e;

    return blinding_context;
  }

  /**
   * Checks if all information are present that are necessary
   * to start the RSA based blind signature creation.
   *
   * For our RSA based blind signatures we need:
   *
   *  - {BigInteger} signers modulus
   *  - {BigInteger} signers public exponent
   *  - {BigInteger} the secret blinded factor
   *  - {BigInteger} hash of the given token to authenticate our request
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  containsAllBlindingInformation()
  {
    return util.isBigInteger(this.modulus)
        && util.isBigInteger(this.public_exponent)
        && util.isBigInteger(this.blinding_factor)
        && util.isBigInteger(this.hashed_token);
  }

  /**
   * To encode RSA signature data the data is first hashed
   * and then encoded with the EMSA-PKCS1-v1_5 method.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {function} hasher
   *    the algorithm used to hash the data
   * @returns {BigInteger}
   *    the encoded and padded rsa signature data
   */
  encode_signature_data(data, hasher)
  {
    assert(util.isBuffer(data));
    assert(util.isFunction(hasher));

    const hashed_data = hasher(data);
    const target_length = this.modulus.mpi_byte_length();

    return pad.emsa_pkcs1_encode(hashed_data, target_length, { hasher: hasher });
  }
}
