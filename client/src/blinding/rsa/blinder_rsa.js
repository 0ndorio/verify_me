"use strict";

import { assert, BigInteger, check, util } from "verifyme_utility"

import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import RsaBlindingContext from "./blinding_context_rsa"
import server  from "../../server_requests"

/**
 * Representation of the rsa blinding algorithm.
 *
 * The variable naming follows the algorithms notation.
 */
export default class RsaBlinder extends Blinder
{
  constructor()
  {
    super();
  }

  /**
   * Initializes the internal {RsaBlindingContext}.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key.
   *    which is necessary to extract the public exponent and
   *    the modulus length.
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  async initContext(key_manager, token)
  {
    assert(check.isKeyManagerForRsaSign(key_manager));
    assert(check.isBigInteger(token));

    let context = RsaBlindingContext.fromKey(key_manager);

    const blinding_factor = await util.generateRsaBlindingFactor(context.modulus.bitLength());
    context.blinding_factor = token.multiply(blinding_factor);
    context.hashed_token = util.calculateSha512(token);

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;
  }

  /**
   * Blinds the given message.
   *
   *    message * blinding_factor^(-1) (mod N)
   *    message * (r ^ ( blinding_fact
   *
   * @param {BigInteger} message
   *    The original message.
   *
   * @returns {BigInteger}
   *    The blinded message.
   */
  blind(message)
  {
    assert(check.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const r = this.context.blinding_factor;
    const e = this.context.public_exponent;
    const N = this.context.modulus;

    return message.multiply(r.modPow(e, N));
  }

  /**
   * Unblinds the given message.
   *
   *    message * blinding_factor^(-1) (mod N)
   *
   * @param {BigInteger} message
   *    The blinded message.
   *
   * @returns {BigInteger}
   *    The unblinded message.
   */
  unblind(message)
  {
    assert(check.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const N = this.context.modulus;
    const r = this.context.blinding_factor;

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  }

  /**
   * Forges a rsa based blind signature.
   *
   * To achieve this the prepared raw signature is blinded and send to the server.
   * The server signs the blinded message and the result is send back.
   * Afterwards the result is unblinded and inject into the given signature packet.
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  async forgeSignature(packet)
  {
    assert(packet instanceof BlindSignaturePacket);
    assert(check.isBigInteger(packet.raw_signature));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const message = packet.raw_signature;
    const blinded_message = this.blind(message);
    const signed_blinded_message = await server.requestRsaBlinding(blinded_message, this.context);
    const signed_message = this.unblind(signed_blinded_message);

    packet.sig = signed_message.to_mpi_buffer();
    packet.raw = packet.write_unframed();
  }
}