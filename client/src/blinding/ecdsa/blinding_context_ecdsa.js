"use strict";

import BlindingContext from "../blinding_context"
import util, { assert } from "../../util"

/**
 * A ecc blinding context.
 */
export default class EcdsaBlindingContext extends BlindingContext
{
  constructor()
  {
    super();

    /** @type {Curve|null} */
    this.curve = null;
    /** @type {Point|null} */
    this.public_point = null;
    /** @type {BigInteger|null} */
    this.hashed_token = null;

    this.blinding_factor = {
      /** @type {BigInteger|null} */
      a: null,
      /** @type {BigInteger|null} */
      b: null,
      /** @type {BigInteger|null} */
      c: null,
      /** @type {BigInteger|null} */
      d: null
    };
  }

  /**
   * Checks if a given {object} is a EcdsaBlindingContext which fulfills all requirements
   * to start the ecdsa blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the ecdsa blind signature creation
   *    else {false}
   */
  static isValidBlindingContext(object)
  {
    return (object instanceof EcdsaBlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the ECC based input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The ECC based public key_manager that belongs to the blind signature issuer.
   * @return {EcdsaBlindingContext}
   *    The generated blinding context.
   */
  static fromKey(key_manager)
  {
    assert(util.isKeyManagerForEcdsaSign(key_manager));

    const public_key_package = key_manager.get_primary_keypair().pub;

    let context = new EcdsaBlindingContext();
    context.curve = public_key_package.curve;

    return context;
  }

  /**
   * Checks if all information are present that are necessary
   * to start the ECDSA based blind signature creation.
   *
   * For our RSA based blind signatures we need:
   *
   *  - {Curve} signers curve
   *  - {BigInteger} hash of the given token to authenticate our request
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  containsAllBlindingInformation()
  {
    return util.isCurve(this.curve)
        && util.isBigInteger(this.hashed_token)
        && null != this.blinding_factor
        && this.blinding_factor.hasOwnProperty("a") && util.isBigInteger(this.blinding_factor.a)
        && this.blinding_factor.hasOwnProperty("b") && util.isBigInteger(this.blinding_factor.b)
        && this.blinding_factor.hasOwnProperty("c") && util.isBigInteger(this.blinding_factor.c)
        && this.blinding_factor.hasOwnProperty("d") && util.isBigInteger(this.blinding_factor.d)
  }

  /**
   * ECDSA signature do not need any further encoding.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {function} hasher
   *    unused
   * @returns {BigInteger}
   *    the incoming signature data stored as {BigInteger}
   */
  encode_signature_data(data, hasher)
  {
    assert(util.isBuffer(data));
    return util.BigInteger.fromBuffer(data);
  }
}
