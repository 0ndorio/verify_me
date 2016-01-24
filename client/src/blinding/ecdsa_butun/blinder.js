"use strict";

import { assert, BigInteger, Buffer, check, util } from "verifyme_utility"

import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import ButunEcdsaBlindingContext from "./blinding_context"
import server from "../../server_requests"

/**
 * Representation of the ECDSA blinding algorithm presented by Ismail Butun and Mehmet Demirer
 * in "A blind digital signature scheme using elliptic curve digital signature algorithm"
 *
 * http://journals.tubitak.gov.tr/elektrik/issues/elk-13-21-4/elk-21-4-4-1102-1051.pdf
 *
 * The variable naming follows the algorithms notation.
 */
export default class ButunEcdsaBlinder extends Blinder
{
  constructor()
  {
    super();
  };

  /**
   * Initializes the internal {ButunEcdsaBlindingContext}.
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

    const context = ButunEcdsaBlindingContext.fromKey(key_manager);
    context.blinding_factor = {
      a: await util.generateRandomScalar(context.curve),
      b: await util.generateRandomScalar(context.curve)
    };

    context.hashed_token = util.calculateSha512(token);

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;
  }

  /**
   * Blinds the given message.
   *
   *    blinding_factor_a * message * signers_public_point * inverse_requester_public_point (mod N)
   *
   * @param {BigInteger} message
   *    The original message.
   * @param {{signer: Point, requester: Point}} public_points
   *    An {object} containing the requesters and
   *    signers public blinding points.
   *
   * @returns {BigInteger}
   *    The blinded message.
   */
  blind(message, public_points)
  {
    assert(check.isBigInteger(message));
    assert(check.isObject(public_points));
    assert(public_points.hasOwnProperty("signer") && check.isPoint(public_points.signer));
    assert(public_points.hasOwnProperty("requester") && check.isPoint(public_points.requester));
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const n = this.context.curve.n;
    const a = this.context.blinding_factor.a;

    const R = public_points.requester;
    const r = R.affineX.mod(n);
    const r_inv = r.modInverse(n);

    const Ŕ = public_points.signer;
    const ŕ = Ŕ.affineX.mod(n);

    return a.multiply(message).multiply(ŕ).multiply(r_inv).mod(n);
  }

  /**
   * Unblinds the given signed blinded message.
   *
   *    (signed_blinded_message * requester_public_point * inverse_signers_public_point)
   *    + (blinding_factor_b * original_message) (mod N)
   *
   * @param {BigInteger} message
   *    The signed blinded message.
   * @param {BigInteger} original_message
   *    The message to be signed.
   * @param {{signer: Point, requester: Point}} public_points
   *    An {object} containing the requesters and
   *    signers public blinding points.
   *
   * @returns {BigInteger}
   *    The unblinded signed message.
   */
  unblind(signed_blinded_message, original_message, public_points)
  {
    assert(check.isBigInteger(signed_blinded_message));
    assert(check.isBigInteger(original_message));
    assert(check.isObject(public_points));
    assert(public_points.hasOwnProperty("signer") && check.isPoint(public_points.signer));
    assert(public_points.hasOwnProperty("requester") && check.isPoint(public_points.requester));
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const n = this.context.curve.n;

    assert(signed_blinded_message.compareTo(BigInteger.ZERO) > 0);
    assert(signed_blinded_message.compareTo(n) < 0);

    const R = public_points.requester;
    const r = R.affineX.mod(n);

    const Ŕ = public_points.signer;
    const ŕ = Ŕ.affineX.mod(n);
    const ŕ_inv = ŕ.modInverse(n);

    const b = this.context.blinding_factor.b;
    const bm = b.multiply(original_message);

    return signed_blinded_message.multiply(r).multiply(ŕ_inv).add(bm).mod(n);
  }

  /**
   * Forges a Butun ecdsa based blind signature.
   *
   * To achieve this the prepared raw signature is blinded and send to the server.
   * The server signs the blinded message and the result is send back.
   * Afterwards the result is unblinded and inject into the given signature packet.
   *
   * Based on: http://journals.tubitak.gov.tr/elektrik/issues/elk-13-21-4/elk-21-4-4-1102-1051.pdf
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  async forgeSignature(packet)
  {
    assert(packet instanceof BlindSignaturePacket);
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const hash = util.calculateSha512(packet.raw_signature);
    const message = packet.key.pub.trunc_hash(hash.toBuffer());

    const public_points = await this.requestPublicPoints();
    const blinded_message = this.blind(message, public_points);

    const signed_blinded_message = await server.requestButunEcdsaBlinding(blinded_message, this.context);
    const signed_message = this.unblind(signed_blinded_message, message, public_points);

    const signature = Buffer.concat([
      signed_message.to_mpi_buffer(),
      this.context.curve.point_to_mpi_buffer(public_points.requester)
    ]);

    packet.sig = signature;
    packet.raw = packet.write_unframed();
  }

  /**
   * Calculates the public blinding information which are
   * Necessary to blind and unblind the message.
   *
   * @returns {{signer: Point, requester: Point}}
   *    Signers and requester public curve point.
   */
  async requestPublicPoints()
  {
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const curve = this.context.curve;
    const n = this.context.curve.n;
    const G = this.context.curve.G;
    const a = this.context.blinding_factor.a;
    const b = this.context.blinding_factor.b;

    const Ŕ = await server.requestButunEcdsaInitialization(this.context);
    assert(curve.isOnCurve(Ŕ));

    const ŕ = Ŕ.affineX.mod(n);
    assert(ŕ.compareTo(BigInteger.ZERO) > 0);
    assert(ŕ.compareTo(n) < 0);

    const aŔ = Ŕ.multiply(a);
    const bG = G.multiply(b);
    const R = aŔ.add(bG);
    assert(curve.isOnCurve(R));

    return { signer: Ŕ, requester: R };
  }
}
