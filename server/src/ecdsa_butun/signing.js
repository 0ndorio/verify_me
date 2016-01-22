"use strict";

import { assert, BigInteger, check, Point, KeyManager, util } from "verifyme_utility"

/// TODO
async function prepareBlinding(key_manager)
{
  assert(check.isKeyManager(key_manager));

  const public_key_package = key_manager.get_primary_keypair().pub;
  const curve = public_key_package.curve;
  const n = curve.n;
  const G = curve.G;

  let k = null;
  let Ŕ = null;
  let ŕ = null;

  do {

    k = await util.generateRandomScalar(curve);
    Ŕ = G.multiply(k);
    ŕ = Ŕ.affineX.mod(n);

  } while(ŕ.compareTo(BigInteger.ZERO) === 0);

  return {k, Ŕ};
}

/// TODO
function sign(message, k, key_manager)
{
  assert(check.isString(message));
  assert(check.isKeyManagerForEcdsaSign(key_manager));
  assert(check.isBigInteger(k));

  const ḿ = new BigInteger(message, 32);

  const key_material = key_manager.get_primary_keypair();
  const n = key_material.pub.curve.n;
  const G = key_material.pub.curve.G;
  const d = key_material.priv.x;

  const Ŕ = G.multiply(k);
  const ŕ = Ŕ.affineX.mod(n);
  const dŕ = d.multiply(ŕ);
  const kḿ = k.multiply(ḿ);

  const ś = dŕ.add(kḿ).mod(n);

  return ś.toRadix(32);
}

const signing_ecdsa_api = {
  prepare: prepareBlinding,
  sign: sign
};

export default signing_ecdsa_api;