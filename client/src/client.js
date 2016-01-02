"use strict";

import ECCBlindingContext from "./types/ecc_blinding_context"
import RSABlindingContext from "./types/rsa_blinding_context"
import BlindSignaturePacket from "./types/blind_signature_packet"
import * as util from "./util"

import * as kbpgp from "kbpgp"

module.exports = {

  /// Constant element ids
  server_public_key_element_id: "server_public_key",
  user_public_key_element_id: "public_key_textarea",
  user_token_element_id: "token_textarea",

  /// Extract users public key from the related textarea
  ///
  /// @return
  ///      public key as kbpgp {KeyManager} object
  getPublicKey: function()
  {
    const public_key_string = this.getPublicKeyString();
    if (public_key_string === null) {
      return Promise.reject(new Error("Couldn't read the public key input. Please reload page."));
    }

    return util.generateKeyFromString(public_key_string);
  },

  /// Extracts users public key from textarea "public_key_textarea".
  ///
  /// @return
  ///      "public_key_textarea" value as {string} or null if the id is missing
  getPublicKeyString: function()
  {
    const content = this.getTextAreaContent(this.user_public_key_element_id);
    if (!util.isString(content)) {
      return null;
    }

    return content.trim();
  },

  /**
   * Extract users token from textarea "token_textarea"
   *
   * @return {BigInteger}
   *    token extracted from input
   */
  getToken: function()
  {
    const token_string = this.getTokenString();
    if (token_string === null) {
      throw new Error("Couldn't read the token input. Please reload page.");
    }

    const token = new util.BigInteger(token_string, 16);
    if (!token.isProbablePrime()) {
      throw new Error("Unsecure Token. Please check your input.");
    }

    return token;
  },

  /// Extracts users token from textarea "token_textarea".
  ///
  /// @return
  ///      "token_textarea" value as {string}
  getTokenString: function()
  {
    const content = this.getTextAreaContent(this.user_token_element_id);
    if (!util.isString(content)) {
      return null;
    }

    return content.trim();
  },

  /// TODO
  getServerPublicKey: function()
  {
    const public_key_string = this.getServerPublicKeyString();
    if (!util.isString(public_key_string)) {
      return Promise.reject(new Error("Couldn't read servers public key. Please reload page."));
    }

    return util.generateKeyFromString(public_key_string);
  },

  /// TODO
  getServerPublicKeyString: function()
  {
    const element = document.getElementById(this.server_public_key_element_id);
    if (element === null) {
      return null;
    }

    return element.innerHTML.trim();
  },

  /// Loads content from textarea with specific id.
  ///
  /// @param {string} text_area_name
  ///      id of the requested text area
  /// @return
  ///      {string} if text area id is valid,
  ///      else {null}
  getTextAreaContent: function(text_area_name)
  {
    if (!util.isString(text_area_name)) { return null; }

    const textarea = document.getElementById(text_area_name);

    let content = null;
    if (textarea !== null) {
      content = textarea.value;
    }

    return content;
  },

  /**
   * Generates a {BlindingContext} for the given {KeyManager}.
   *
   * @param {KeyManager} public_key
   *    The {KeyManager} containing the public_key we want to use to create a signature.
   * @return
   *    A {BlindingContext} related to the public key algorithm used to create the input key.
   */
  generateBlindingContext: function(public_key, token)
  {
    if (!util.isKeyManager(public_key)) {
      throw new Error("Input parameter is no {KeyManager} object.");
    }

    const tags = kbpgp.const.openpgp.public_key_algorithms;
    const public_key_algorithm = public_key.get_primary_keypair().get_type();

    let context = null;
    switch (public_key_algorithm) {
      case tags.RSA:
      case tags.RSA_SIGN_ONLY: {
        context = RSABlindingContext.fromKey(public_key);
        break;
      }
      case tags.ECDSA: {
        context = ECCBlindingContext.fromKey(public_key);
        break;
      }
      case tags.RSA_ENCRYPT_ONLY:
        throw new Error("Requested public key algorithm is for encryption only.");
      default:
        throw new Error("Unsupported public key algorithm id: " + public_key_algorithm);
    }

    context.hashed_token = util.hashMessage(token.toRadix());

    return context;
  },

  sendBlindingRequest: function(blinded_message, blinding_context)
  {
    if (!util.isString(blinded_message)) {
      return Promise.reject(new Error("blinded_message is not type of string but '" + typeof blinded_message + "'"));
    }

    if(!(blinding_context instanceof RSABlindingContext && util.isBigInteger(blinding_context.hashed_token))) {
      return Promise.reject(new Error("no hashed token stored in blinding_context"));
    }

    const message = JSON.stringify({
      message: blinded_message,
      token_hash: blinding_context.hashed_token.toString(16)
    });

    return this.generateBlindingRequestPromise(message);
  },

  generateBlindingRequestPromise: function (message) {

    if (!util.isString(message)) {
      return Promise.reject("Message is not of type string but '" + typeof messsage + "'");
    }

    return new Promise((resolve, reject) => {

      let xhttp = new XMLHttpRequest();
      xhttp.open("POST", "/");
      xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");

      xhttp.onload = () => {

        if (xhttp.readyState === 4 && xhttp.status === 200) {
          resolve(xhttp.responseText);
        } else {
          reject(new Error(xhttp.statusText));
        }
      };

      xhttp.onerror = (error) => { reject(new Error("error handler called with: " + error)) };

      xhttp.send(message);
    });
  },

  prepareBlindSignatureRequest: async function ()
  {
    const public_key = await this.getPublicKey();
    const server_public_key = await this.getServerPublicKey();
    const token = this.getToken();

    const context = this.generateBlindingContext(server_public_key, token);
    const packet = new BlindSignaturePacket(public_key, server_public_key);
    
    return { context, packet, token };
  }
};
