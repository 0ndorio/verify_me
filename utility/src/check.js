"use strict";

import { BigInteger, Buffer, Curve, KeyManager, Point, Tags } from "./types"

/**
 * Client runtime assert.
 * Throws if the given condition validates to {false} else nothing happens.
 *
 * @param {boolean} condition
 *    Validated condition.
 * @param {string|null} message
 *    Custom assert message.
 */
function assert(condition, message)
{
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

/**
 * Checks if the given object is a {BigInteger}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {BigInteger}
 *    else {false}
 */
function isBigInteger(object)
{
  return isObject(object) && (object.constructor.name === BigInteger.name);
}

/**
 * Checks if the given object is a {Buffer}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Buffer}
 *    else {false}
 */
function isBuffer(object)
{
  return isObject(object) && (object instanceof Buffer);
}

/**
 * Checks if the given element is an ecc {Curve}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Curve}
 *    else {false}
 */
function isCurve(object)
{
  return isObject(object) && (object instanceof Curve);
}

/**
 * Checks if the given element is a {function}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {function}
 *    else {false}
 */
function isFunction(object)
{
  return (typeof object === "function");
}

/**
 * Checks if the given element is an integer {number}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is an integer
 *    else {false}
 */
function isInteger(object)
{
  return (typeof object === "number") && (object % 1 === 0);
}

/**
 * Checks if the given element is an {object}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is an {object}
 *    else {false}
 */
function isObject(object)
{
  return object === Object(object);
}

/**
 * Checks if the given object is a valid {KeyManager}.
 *
 * @param {*} key_manager
 *
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager}
 *    else {false}.
 */
function isKeyManager(key_manager)
{
  return (key_manager instanceof KeyManager)
      && (key_manager.get_primary_keypair() !== null);
}

/**
 * Checks if the given object is a valid {KeyManager} which
 * contains a ECDSA based key_manager.
 *
 * @param {KeyManager} key_manager
 *    The object that is checked for the used algorithm.
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager} that can be
 *    used to sign based on the ECDSA algorithm else {false}.
 */
function isKeyManagerForEcdsaSign(key_manager)
{
  if (!isKeyManager(key_manager)) { return false; }

  const tags = Tags.public_key_algorithms;
  const key_algorithm = key_manager.get_primary_keypair().get_type();

  return (key_algorithm === tags.ECDSA);
}

/**
 * Checks if the given object is a valid {KeyManager} which
 * contains a RSA or RSA_SIGN_ONLY based key_manager.
 *
 * @param {KeyManager} key_manager
 *    The object that is checked for the used algorithm.
 * @returns {boolean}
 *    {true} if the given object is a {KeyManager} that can be used
 *    to sign based on the RSA algorithm else {false}.
 */
function isKeyManagerForRsaSign(key_manager)
{
  if (!isKeyManager(key_manager)) { return false; }

  const key_algorithm = key_manager.get_primary_keypair().get_type();
  const tags = Tags.public_key_algorithms;

  return (key_algorithm === tags.RSA) || (key_algorithm === tags.RSA_SIGN_ONLY);
}

/**
 * Checks if the given element is a {Point}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Point}
 *    else {false}
 */
function isPoint(object)
{
  return isObject(object) && (object instanceof Point);
}

/**
 * Checks if the given element is a {string}.
 *
 * @param {*} object
 *
 * @returns {boolean}
 *    {true} if the given element is a {Point}
 *    else {false}
 */
function isString(object)
{
  return (typeof object === "string");
}

const check_api = {
  assert,
  isBigInteger,
  isBuffer,
  isCurve,
  isFunction,
  isInteger,
  isKeyManager,
  isKeyManagerForEcdsaSign,
  isKeyManagerForRsaSign,
  isObject,
  isPoint,
  isString
};

export default check_api;
export { assert };
