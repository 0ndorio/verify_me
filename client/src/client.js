"use strict";

import RSABlindingContext from "./types/rsa_blinding_context"
import BlindSignaturePacket from "./types/blind_signature_packet"
import * as util from "./util"

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

  /// TODO
  generateRSABlindingContext: async function()
  {
    const server_public_key = await this.getServerPublicKey();
    let context = RSABlindingContext.fromKey(server_public_key);

    const token = this.getToken();
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
    const context = await this.generateRSABlindingContext();

    return {
      context: context,
      packet: new BlindSignaturePacket(public_key, server_public_key),
      token: this.getToken()
    };
  }
};
