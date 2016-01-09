"use strict";

import Blinder from "../blinder"
import RsaBlindingContext from "./blinding_context_rsa"
import * as util from "../../util"
const assert = util.assert;

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
}