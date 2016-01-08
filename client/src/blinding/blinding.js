"use strict";
import EcdsaBlindingContext from "./blinding_context_ecdsa"
import RsaBlindingContext from "./blinding_context_rsa"
import * as util from "./../util"
const assert = util.assert;

/// TODO
function blind_message(message, blinding_context)
{
  let blinding_function = null;

  if (RsaBlindingContext.isValidBlindingContext(blinding_context)) {
    blinding_function = this.blind_message_rsa;
  } else if (EcdsaBlindingContext.isValidBlindingContext(blinding_context)) {
    blinding_function = this.blind_message_ecdsa;
  }

  assert(util.isBigInteger(message));
  assert(null !== blinding_function);
  return blinding_function(message, blinding_context);
}

/// TODO
function blind_message_rsa(message, blinding_context)
{
  assert(util.isBigInteger(message));
  assert(RsaBlindingContext.isValidBlindingContext(blinding_context));

  const r = blinding_context.blinding_factor;
  const e = blinding_context.public_exponent;
  const N = blinding_context.modulus;

  return message.multiply(r.modPow(e, N));
}

/// TODO
function blind_message_ecdsa(message, blinding_context)
{
  assert(util.isBigInteger(message));
  assert(EcdsaBlindingContext.isValidBlindingContext(blinding_context));

  return null;
}

/**
 * Generates a {BlindingContext} for the given {KeyManager}.
 *
 * @param {KeyManager} public_key
 *    The {KeyManager} containing the public_key we want to use to create a signature.
 * @return
 *    A {BlindingContext} related to the public key algorithm used to create the input key.
 */
async function generateBlindingContext(public_key, token)
{
  assert(util.isKeyManager(public_key));
  assert(util.isBigInteger(token));

  const tags = util.public_key_algorithms_tags;
  const public_key_algorithm = public_key.get_primary_keypair().get_type();

  let context = null;
  switch (public_key_algorithm) {
    case tags.RSA:
    case tags.RSA_SIGN_ONLY: {
      context = RsaBlindingContext.fromKey(public_key);

      const blinding_factor = await util.generateBlindingFactor(context.modulus.bitLength());
      context.blinding_factor = token.multiply(blinding_factor);

      break;
    }
    case tags.ECDSA: {
      context = EcdsaBlindingContext.fromKey(public_key);
      break;
    }
    case tags.RSA_ENCRYPT_ONLY:
      throw new Error("Requested public key algorithm is for encryption only.");
    default:
      throw new Error("Unsupported public key algorithm id: " + public_key_algorithm);
  }

  context.hashed_token = util.hashMessage(token.toRadix());

  return context;
}

/// TODO
function unblind_message(message, blinding_context)
{
  let blinding_function = null;

  if (RsaBlindingContext.isValidBlindingContext(blinding_context)) {
    blinding_function = this.unblind_message_rsa;
  } else if (EcdsaBlindingContext.isValidBlindingContext(blinding_context)) {
    blinding_function = this.unblind_message_ecdsa;
  }

  assert(util.isBigInteger(message));
  assert(null !== blinding_function);
  return blinding_function(message, blinding_context);
}

/// TODO
function unblind_message_rsa(message, blinding_context)
{
  assert(util.isBigInteger(message));
  assert(RsaBlindingContext.isValidBlindingContext(blinding_context));

  const N = blinding_context.modulus;
  const r = blinding_context.blinding_factor;

  const r_inv = r.modInverse(N);
  return message.multiply(r_inv).mod(N);
}

/// TODO
function unblind_message_ecdsa(message, blinding_context)
{
  assert(util.isBigInteger(message));
  assert(EcdsaBlindingContext.isValidBlindingContext(blinding_context));

  return null;
}

const blinding_api = {
  blind_message,
  blind_message_ecdsa,
  blind_message_rsa,
  generateBlindingContext,
  unblind_message,
  unblind_message_ecdsa,
  unblind_message_rsa
};

export default blinding_api;