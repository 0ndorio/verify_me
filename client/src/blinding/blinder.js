"use strict";

import { KeyManager } from "kbpgp"

import util from "./../util"
const assert = util.assert;

/**
 * TODO
 */
export default class Blinder
{
  constructor(key_manager)
  {
    assert(this.constructor.name !== "Blinder", "Cannot construct Blinding instances directly");
    assert(util.isKeyManager(key_manager));

    /** @type {KeyManager|null} **/
    this.key_manager = key_manager;

    /** @type {BigInteger|null} **/
    this.token = null;

    /** @type {BlindingContext|null} **/
    this.context = null;
  }

  /// TODO
  async initContext()
  {
    throw new Error("Not yet implemented.");
  }

  /// TODO
  blind()
  {
    throw new Error("Not yet implemented");
  }

  // TODO
  unblind()
  {
    throw new Error("Not yet implemented");
  }
}