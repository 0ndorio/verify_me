"use strict";

import { Buffer, KeyManager, Tags } from "verifyme_utility"

/**
 * An abstract blinding context object.
 * 
 * An algorithm specific full valid blinding context stores all
 * information that are necessary to complete the related blind
 * and unblinding steps.
 */
export default class BlindingContext
{
  constructor()
  {
    if (this.constructor.name === "BlindingContext") {
      throw new TypeError("Cannot construct BlindingContext instances directly");
    }

    /** @type {BigInteger|null} */
    this.hashed_token = null;
  }

  /**
   * Checks if a given {object} is a BlindingContext which fulfills all requirements
   * to start the blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the blind signature creation
   *    else {false}
   */
  static isValidBlindingContext(object)
  {
    return (object instanceof BlindingContext) && object.containsAllBlindingInformation();
  }
  
  /**
   * Generates a blinding context based on the public information
   * extracted from the input {KeyManager} object.
   * 
   * @param {KeyManager} key_manager
   *    The public key_manager that belongs to the blind signature issuer.
   * @return {BlindingContext}
   *    The generated blinding context.   
   */
  static fromKey(key_manager)
  {
    throw new Error("Not yet implemented.");
  }

  /**
   * Checks if all information are present that are necessary
   * to start the blind signature creation.
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  containsAllBlindingInformation()
  {
    throw new Error("Not yet implemented.");
  }

  /**
   * Encodes raw signature data to fit the pgp standard for signatures of
   * the used public key algorithm.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {function} hasher
   *    unused
   * @returns {BigInteger}
   *    the incoming signature data stored as {BigInteger}
   */
  encodeSignaturePayload(data, hasher)
  {
    throw new Error("Not yet implemented.");
  }

  /**
   * Returns the id of the verification algorithm.
   *
   * @return {number}
   *    Id of the algorithm to verify a signature
   *    generated with this blinding context.
   */
  verificationAlgorithm()
  {
    return Tags.verification_algorithms.default;
  }
}
