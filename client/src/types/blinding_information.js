"use strict";

import * as util from "../util"

/**
 * A rsa blinding context.
 * @constructor
 * @struct
 */
function BlindingInformation()
{
  /** @type {BigInteger|null} */
  this.blinding_factor = null;
  /** @type {BigInteger|null} */
  this.hashed_token = null;
  /** @type {BigInteger|null} */
  this.modulus = null;
  /** @type {BigInteger|null} */
  this.public_exponent = null;
}

/// TODO
BlindingInformation.prototype.containsPublicBlindingInformation = function()
{
  return (util.isBigInteger(this.modulus) && util.isBigInteger(this.public_exponent));
};

/// TODO
BlindingInformation.prototype.containsAllBlindingInformation = function()
{
  return this.containsPublicBlindingInformation()
    && util.isBigInteger(this.blinding_factor)
    && util.isBigInteger(this.hashed_token);
};

/// TODO
BlindingInformation.prototype.fromKey = function(key)
{
  if (!util.isOpenPGPKey(key)) {
    return false;
  }

  var public_key_package = key.get_primary_keypair().pub;
  this.modulus = public_key_package.n;
  this.public_exponent = public_key_package.e;

  return true;
};

/// TODO
BlindingInformation.isValidFullBlindingInformation = function(blinding_information)
{
  return (blinding_information instanceof BlindingInformation)
    && blinding_information.containsAllBlindingInformation();
};

/// TODO
BlindingInformation.isValidPublicBlindingInformation = function(blinding_information)
{
  return (blinding_information instanceof BlindingInformation)
    && blinding_information.containsPublicBlindingInformation();
};

module.exports = BlindingInformation;
