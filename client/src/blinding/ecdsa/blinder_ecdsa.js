"use strict";

import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import server from "../../server"
import util, { assert, Point, BigInteger } from "../../util"

/// TODO
/// http://www.eng.usf.edu/~ibutun/ELK-1102-1051_manuscript_1.pdf
export default class EcdsaBlinder extends Blinder
{
  constructor(key_manager)
  {
    super(key_manager);
  }

  /// TODO
  async initContext(key_manager, token)
  {
    assert(util.isKeyManagerForEcdsaSign(key_manager));
    assert(util.isBigInteger(token));

    const context = EcdsaBlindingContext.fromKey(key_manager);
    context.hashed_token = util.hashMessage(token.toRadix());

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;
  }

  /// TODO
  blind(message)
  {
    assert(util.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    return null;
  }

  /// TODO
  unblind(message)
  {
    assert(util.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    return null;
  }

  /// TODO
  async forgeSignature(packet)
  {
    assert(packet instanceof BlindSignaturePacket);
    assert(util.isBigInteger(packet.raw_signature));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const R = await server.requestEcdsaBlindingInitialization(this.context);

    const message = packet.raw_signature;
    const blinded_message = this.blind(message);
    const signed_blinded_message = null;
    const signed_message = null;

    //packet.sig = signed_message.to_mpi_buffer();
  }
}