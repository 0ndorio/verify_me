"use strict";

import { Buffer, hash } from "kbpgp"
import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import server from "../../server"
import util, { assert, Point, BigInteger } from "../../util"

/// TODO
/// http://oleganza.com/blind-ecdsa-draft-v2.pdf
export default class EcdsaBlinder extends Blinder
{
  constructor(key_manager)
  {
    super(key_manager);
  };

  /// TODO
  async initContext(key_manager, token)
  {
    assert(util.isKeyManagerForEcdsaSign(key_manager));
    assert(util.isBigInteger(token));

    const context = EcdsaBlindingContext.fromKey(key_manager);
    context.blinding_factor.a = await this.generate_random_scalar(context.curve);
    context.blinding_factor.b = await this.generate_random_scalar(context.curve);
    context.blinding_factor.c = await this.generate_random_scalar(context.curve);
    context.blinding_factor.d = await this.generate_random_scalar(context.curve);
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

    const n = this.context.curve.n;
    const a = this.context.blinding_factor.a;
    const b = this.context.blinding_factor.b;

    return message.multiply(a).add(b).mod(n);
  }

  /// TODO
  unblind(message, secrets)
  {
    assert(util.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const n = this.context.curve.n;
    const c = this.context.blinding_factor.c;
    const d = this.context.blinding_factor.d;

    return c.multiply(message).add(d).mod(n);
  }

  /// TODO
  async forgeSignature(packet)
  {
    assert(packet instanceof BlindSignaturePacket);
    assert(util.isBigInteger(packet.raw_signature));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const { T, r }  = await this.generatePublicInformation();

    const message_buffer = hash.SHA512(packet.raw_signature.toBuffer());
    const message = packet.key.pub.trunc_hash(message_buffer);
    const blinded_message = this.blind(message);
    const signed_blinded_message = await server.requestEcdsaBlinding(blinded_message, this.context);
    const signed_message = this.unblind(signed_blinded_message);

    packet.sig = Buffer.concat([r.to_mpi_buffer(), signed_message.to_mpi_buffer()]);
    packet.key.pub.R = T;
  }

  /// TODO
  async generatePublicInformation()
  {
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const a = this.context.blinding_factor.a;
    const b = this.context.blinding_factor.b;
    const c = this.context.blinding_factor.c;
    const d = this.context.blinding_factor.d;

    const curve = this.context.curve;
    const n = curve.n;

    // request initial points based on secret scalars
    const { P, Q } = await server.requestEcdsaBlindingInitialization(this.context);
    assert(curve.isOnCurve(P));
    assert(curve.isOnCurve(Q));

    const ca_inv = c.multiply(a).modInverse(n);
    const K = P.multiply(ca_inv);
    assert(curve.isOnCurve(K));

    const aKx_inv = a.multiply(K.affineX).modInverse(n);
    const bG = curve.G.multiply(b);
    assert(curve.isOnCurve(bG));

    const c_inv = c.modInverse(n);
    const T = (P.multiply(c_inv).multiply(d).add(Q).add(bG)).multiply(aKx_inv);
    assert(curve.isOnCurve(T));

    return { T, r: K.affineX};
  }

  /**
   * Generate a random scalar k.
   *
   * k is in range [1, n-1] where n is the prime number defining
   * the order of the givens curves base point.
   *
   * @param {Curve} curve
   *    The curve we use to generate the random scalar value.
   * @returns {Promise}
   *    The promise of a {BigInteger} scalar [1, n-1]
   */
  async generate_random_scalar(curve)
  {
    return new Promise((resolve, reject) =>
      curve.random_scalar(
        k => resolve(k))
    );
  }
}