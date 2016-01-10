"use strict";

import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import RsaBlindingContext from "./blinding_context_rsa"
import server  from "../../server"
import util, { assert } from "../../util"

/// TODO
export default class RsaBlinder extends Blinder
{
  constructor(key_manager)
  {
    super(key_manager);
  }

  /// TODO
  async initContext()
  {
    assert(util.isBigInteger(this.token));
    assert(util.isKeyManagerForRsaSign(this.key_manager));

    let context = RsaBlindingContext.fromKey(this.key_manager);

    const blinding_factor = await util.generateBlindingFactor(context.modulus.bitLength());
    context.blinding_factor = this.token.multiply(blinding_factor);
    context.hashed_token = util.hashMessage(this.token.toRadix());

    this.context = context;
  }

  /// TODO
  blind(message)
  {
    assert(util.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const r = this.context.blinding_factor;
    const e = this.context.public_exponent;
    const N = this.context.modulus;

    return message.multiply(r.modPow(e, N));
  }

  /// TODO
  unblind(message)
  {
    assert(util.isBigInteger(message));
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
    assert(util.isBigInteger(packet.raw_signature));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const message = packet.raw_signature;
    const blinded_message = this.blind(message);
    const signed_blinded_message = await server.sendBlindingRequest(blinded_message, this.context);
    const signed_message = this.unblind(signed_blinded_message);

    packet.sig = signed_message.to_mpi_buffer();
  }
}