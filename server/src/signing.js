"use strict";

import { rsa_promise, ecc_promise } from "./keys"

export function sign_blinded_rsa_message()
{
  return rsa_promise.then((key_manager) => {
    return key_manager.armored_pgp_private;
  });
}

export function sign_blinded_ecdsa_mesage()
{
  return ecc_promise.then((key_manager) => {
    return key_manager.armored_pgp_private;
  });
}