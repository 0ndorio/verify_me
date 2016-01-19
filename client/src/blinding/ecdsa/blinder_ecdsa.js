"use strict";

import { hash } from "kbpgp"
import { assert, BigInteger, Buffer, check, util } from "verifyme_utility"

import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import server from "../../server_requests"

/**
 * Representation of the ECDSA blinding algorithm presented by Oleg Andreev
 * in https://github.com/oleganza/bitcoin-papers/blob/master/BitcoinBlindSignatures.md
 *
 * The variable naming follows the algorithms notation.
 */
export default class EcdsaBlinder extends Blinder
{
  constructor()
  {
    super();
  };

  /**
   * Initializes the internal {EcdsaBlindingContext}.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key which is necessary
   *    to extract the elliptic curve public parameter.
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  async initContext(key_manager, token)
  {
    assert(check.isKeyManagerForEcdsaSign(key_manager));
    assert(check.isBigInteger(token));

    const context = EcdsaBlindingContext.fromKey(key_manager);
    context.blinding_factor = {
      a: await util.generateRandomScalar(context.curve),
      b: await util.generateRandomScalar(context.curve),
      c: await util.generateRandomScalar(context.curve),
      d: await util.generateRandomScalar(context.curve)
    };

    context.hashed_token = util.hashMessageSha512(token.toRadix());

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;
  }

  /**
   * Blinds the given message.
   *
   *    (message * blinding_factor_a) + blinding_factor_b (mod N)
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
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const n = this.context.curve.n;
    const a = this.context.blinding_factor.a;
    const b = this.context.blinding_factor.b;

    return message.multiply(a).add(b).mod(n);
  }

  /**
   * Unblinds the given signed blinded message.
   *
   *    (signed_blinded_message * blinding_factor_c) + blinding_factor_d (mod N)
   *
   * @param {BigInteger} message
   *    The signed blinded message.
   *
   * @returns {BigInteger}
   *    The unblinded signed message.
   */
  unblind(message)
  {
    assert(check.isBigInteger(message));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const n = this.context.curve.n;
    const c = this.context.blinding_factor.c;
    const d = this.context.blinding_factor.d;

    return message.multiply(c).add(d).mod(n);
  }

  /**
   * Forges a ecdsa based blind signature.
   *
   * To achieve this the prepared raw signature is blinded and send to the server.
   * The server signs the blinded message and the result is send back.
   * Afterwards the result is unblinded and inject into the given signature packet.
   *
   * Based on: https://github.com/oleganza/bitcoin-papers/blob/master/BitcoinBlindSignatures.md
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  async forgeSignature(packet)
  {
    assert(packet instanceof BlindSignaturePacket);

    const { T, r }  = await this.requestFirstSignatureParameter();
    const s = await this.requestSecondSignatureParameter(packet);

    assert(r.compareTo(BigInteger.ZERO) > 0);
    assert(s.compareTo(BigInteger.ZERO) > 0);

    packet.sig = Buffer.concat([r.to_mpi_buffer(), s.to_mpi_buffer()]);
    packet.key.pub.R = T;
    packet.raw = packet.write_unframed();
  }

  /**
   * Calculates the first part of the ECDSA signature.
   * Based on the public information published by the signer.
   *
   * @returns {{T: Point, r: BigInteger}}
   *    T is the public key necessary to validate the final signature.
   *    r is the first part of the ECDSA signature.
   */
  async requestFirstSignatureParameter()
  {
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const curve = this.context.curve;
    const n = curve.n;

    const a = this.context.blinding_factor.a;
    const b = this.context.blinding_factor.b;
    const c = this.context.blinding_factor.c;
    const d = this.context.blinding_factor.d;

    const { P, Q } = await server.requestEcdsaBlindingInitialization(this.context);
    assert(curve.isOnCurve(P));
    assert(curve.isOnCurve(Q));

    const ca_inv = c.multiply(a).modInverse(n);
    const K = P.multiply(ca_inv);
    assert(curve.isOnCurve(K));

    const r = K.affineX;
    const ar_inv = a.multiply(r).modInverse(n);
    const bG = curve.G.multiply(b);
    assert(curve.isOnCurve(bG));

    const c_inv = c.modInverse(n);
    const T = (P.multiply(c_inv).multiply(d).add(Q).add(bG)).multiply(ar_inv);
    assert(curve.isOnCurve(T));

    return { T, r };
  }

  /**
   * Calculates the second part of the ECDSA signature.
   * Based on the blinded key packet payload send to the signer.
   *
   * @param {BlindSignaturePacket} packet
   *    Key package with prepared raw signature data.
   * @returns {BigInteger}
   *    The unblinded signed signature data.
   */
  async requestSecondSignatureParameter(packet)
  {
    assert(packet instanceof BlindSignaturePacket);
    assert(check.isBigInteger(packet.raw_signature));
    assert(EcdsaBlindingContext.isValidBlindingContext(this.context));

    const message_buffer = hash.SHA512(packet.raw_signature.toBuffer());
    const message = packet.key.pub.trunc_hash(message_buffer);
    const blinded_message = this.blind(message);
    const signed_blinded_message = await server.requestEcdsaBlinding(blinded_message, this.context);
    return this.unblind(signed_blinded_message);
  }
}