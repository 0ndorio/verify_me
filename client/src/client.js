"use strict";

import * as kbpgp from "kbpgp"
import { check } from "verifyme_utility"

/// Constant element ids
const server_public_key_element_id = "server_public_key";
const user_public_key_element_id = "public_key_textarea";
const user_token_element_id = "token_textarea";

/**
 *  Extract users public key from the related textarea
 *
 * @returns {Promise}
 *    the promise of a the users public key managed
 *    in a kbpgp {KeyManager}
 */
function getPublicKey()
{
  const public_key_string = getPublicKeyString();
  if (public_key_string === null) {
    return Promise.reject(new Error("Couldn't read the public key input. Please reload page."));
  }

  return check.generateKeyFromString(public_key_string);
}

/**
 * Extracts users public key from the textarea element with id "public_key_textarea".
 *
 * @returns {string|null}
 *    string value of the dom element with id "public_key_textarea"
 *    or {null} if the element is missing.
 */
function getPublicKeyString()
{
  const content = getTextAreaContent(user_public_key_element_id);
  if (!check.isString(content)) {
    return null;
  }

  return content.trim();
}

/**
 * Extract users token from textarea "token_textarea"
 *
 * @return {BigInteger}
 *    token extracted from input
 */
function getToken()
{
  const token_string = getTokenString();
  if (token_string === null) {
    throw new Error("Couldn't read the token input. Please reload page.");
  }

  const token = new check.BigInteger(token_string, 16);
  if (!token.isProbablePrime()) {
    throw new Error("Unsecure Token. Please check your input.");
  }

  return token;
}

/**
 * Extracts users token from textarea element with id "token_textarea".
 *
 * @returns {string}
 *    string value of the dom element with id "token_textarea"
 *    or {null} if the element is missing.
 */
function getTokenString()
{
  const content = getTextAreaContent(user_token_element_id);
  if (!check.isString(content)) {
    return null;
  }

  return content.trim();
}

/**
 *  Extract servers public key from the related textarea
 *
 * @returns {Promise}
 *    the promise of a the servers public key managed
 *    in a kbpgp {KeyManager}
 */
function getServerPublicKey()
{
  const public_key_string = getServerPublicKeyString();
  if (!check.isString(public_key_string)) {
    return Promise.reject(new Error("Couldn't read servers public key. Please reload page."));
  }

  return check.generateKeyFromString(public_key_string);
}

/**
 * Extracts servers public key from the textarea element with id "server_public_key".
 *
 * @returns {string|null}
 *    string value of the dom element with id "server_public_key"
 *    or {null} if the element is missing.
 */
function getServerPublicKeyString()
{
  const element = document.getElementById(server_public_key_element_id);
  if (element === null) {
    return null;
  }

  return element.innerHTML.trim();
}

/**
 * Loads content from a textarea specified by the given element id.
 *
 * @param {string} text_area_name
 *    id of the requested text area
 * @returns {*}
 *    {string} if text area id is valid,
 *    else {null}
 */
function getTextAreaContent(text_area_name)
{
  if (!check.isString(text_area_name)) { return null; }

  const textarea = document.getElementById(text_area_name);

  let content = null;
  if (textarea !== null) {
    content = textarea.value;
  }

  return content;
}

const client_api = {
  getPublicKey,
  getPublicKeyString,
  getServerPublicKey,
  getServerPublicKeyString,
  getTextAreaContent,
  getToken,
  getTokenString,
  server_public_key_element_id,
  user_public_key_element_id,
  user_token_element_id
};

export default client_api