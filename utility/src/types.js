"use strict";

import * as kbpgp from "kbpgp"

export const Buffer = kbpgp.Buffer;
export const Curve = kbpgp.ecc.curves.Curve;
export const KeyManager = kbpgp.KeyManager;
export const Tags = {
  public_key_algorithms: kbpgp.const.openpgp.public_key_algorithms
};

export { BigInteger } from "../node_modules/kbpgp/lib/bn"
export { Point } from "keybase-ecurve"