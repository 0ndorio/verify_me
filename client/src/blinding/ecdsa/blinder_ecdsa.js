"use strict";

import { Buffer, hash } from "kbpgp"
import Blinder from "../blinder"
import BlindSignaturePacket from "../../pgp/blind_signature_packet"
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import server from "../../server"
import util, { assert, Point, BigInteger } from "../../util"

/// TODO
/// http://www.eng.usf.edu/~ibutun/ELK-1102-1051_manuscript_1.pdf
/// https://en.wikipedia.org/wiki/Acute_accent
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

    // prepare algorithm
    const curve = this.context.curve;
    const n = curve.n;

    // request initial point based on secret scalar
    const Ŕ = await server.requestEcdsaBlindingInitialization(this.context);
    assert(curve.isOnCurve(Ŕ));

    // calculate rx
    const ŕ = Ŕ.affineX.mod(n);
    assert(0 !== ŕ.compareTo(util.BigInteger.ZERO));

    // choose random scalars a,b [1, n-1]
    const A = await generate_random_scalar(curve);
    const B = await generate_random_scalar(curve);

    // calculate second point based on random scalars
    const R = Ŕ.multiplyTwo(A, curve.G, B);
    assert(curve.isOnCurve(R));

    const r = R.affineX.mod(n);
    const r_inv = r.modInverse(n);

    // generate blinded message
    const message_buffer = hash.SHA1(packet.raw_signature.toBuffer());
    const hashed_message = BigInteger.fromBuffer(message_buffer);
    this.signed_hash_value_hash = hashed_message.toBuffer().slice(0, 2);

    const ḿ = A.multiply(hashed_message).multiply(ŕ).multiply(r_inv).mod(n);

    // request signed blinded message
    let ś = await server.requestEcdsaBlinding(ḿ, this.context);
    ś = ś.mod(n);

    // verify valid data (ś and ŕ in [1, n-1])
    assert(0 < ś.compareTo(util.BigInteger.ZERO) && 0 > ś.compareTo(n));
    assert(0 < ŕ.compareTo(util.BigInteger.ZERO) && 0 > ŕ.compareTo(n));

    // unblinde signed message
    const ŕ_inv = ŕ.modInverse(n);
    const s = ś.multiply(r).multiply(ŕ_inv).add(B.multiply(hashed_message)).mod(n);

    //const message = packet.raw_signature;
    //const blinded_message = this.blind(message);
    //const signed_blinded_message = null;
    //const signed_message = null;

    // paper suggest (s, R) but ecdsa says (r, s)
    packet.sig = Buffer.concat([r.to_mpi_buffer(), s.to_mpi_buffer()]);
  }
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
async function generate_random_scalar(curve)
{
  return new Promise((resolve, reject) =>
    curve.random_scalar(
      k => resolve(k))
  );
}