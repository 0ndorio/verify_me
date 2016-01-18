"use strict";

import { KeyManager } from "kbpgp"

import util from "verifyme_utility"
const assert = util.assert;

/**
 * Representation of a blinding algorithm.
 */
export default class Blinder
{
  /**
   * Creates a blinding algorithm representation based
   */
  constructor()
  {
    assert(this.constructor.name !== "Blinder", "Cannot construct Blinding instances directly");

    /** @type {KeyManager|null} **/
    this.key_manager = null;

    /** @type {BigInteger|null} **/
    this.token = null;

    /** @type {BlindingContext|null} **/
    this.context = null;
  }

  /**
   * Blinding context initialization.
   * Could be possibly async so its not done by the constructor.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key.
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  async initContext(key_manager, token)
  {
    throw new Error("Not yet implemented.");
  }

  /**
   * Blinds a given message.
   *
   * @param {BigInterger} message
   *    The message to blind.
   * @return {BigInteger}
   *    The blinded message.
   */
  blind(message)
  {
    throw new Error("Not yet implemented");
  }

  /**
   * Unblinds a given messsage.
   *
   * @param {BigInteger} message
   *    The blinded message.
   * @return {BigInteger}
   *    The unblinded message.
   */
  unblind(message)
  {
    throw new Error("Not yet implemented");
  }

  /**
   * Forges a blind signature.
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  async forgeSignature(packet)
  {
    throw new Error("Not yet implemented");
  }
}
