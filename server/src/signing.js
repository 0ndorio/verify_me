"use strict";

import { KeyManager } from "kbpgp"
import { BigInteger } from "../node_modules/kbpgp/lib/bn"

import { rsa_promise, ecc_promise } from "./keys"

export function sign_blinded_rsa_message(message, key_manager)
{
  if (typeof message !== "string") {
    throw new Error("message is not of type string");
  }

  if (!(key_manager instanceof KeyManager)) {
    throw new Error("key_manager is no intance of KeyManager");
  }

  const key_pair = key_manager.get_primary_keypair();

  const m = new BigInteger(message, 16);
  const n = key_pair.pub.n;
  const d = key_pair.priv.d;

  return m.modPow(d, n).toRadix(16);
}

export function sign_blinded_ecdsa_mesage(message, key_manager)
{
}