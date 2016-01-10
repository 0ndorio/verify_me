"use strict";

import Blinder from "../blinder"
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import util, { assert } from "../../util"

/// TODO
export default class EcdsaBlinder extends Blinder
{
  constructor(key_manager)
  {
    super(key_manager);
  }

  /// TODO
  async initContext(key_manager, token)
  {
    this.key_manager = key_manager;
    this.context = EcdsaBlindingContext.fromKey(key_manager);
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
}