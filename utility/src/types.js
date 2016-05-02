"use strict";

import * as kbpgp from "kbpgp"

export const BigInteger = kbpgp.bn.BigInteger;
export const Buffer = kbpgp.Buffer;
export const Curve = kbpgp.ecc.curves.Curve;
export const KeyManager = kbpgp.KeyManager;
export const Tags = {
  public_key_algorithms: kbpgp.const.openpgp.public_key_algorithms,
  verification_algorithms: kbpgp.const.openpgp.verification_algorithms
};

export { Point } from "keybase-ecurve"
