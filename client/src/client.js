"use strict";

var BlindingInformation= require("./types/blinding_information");
var util = require("./util");

module.exports = {

  /// Constant element ids
  server_public_key_element_id: "server_public_key",
  user_public_key_element_id: "public_key_textarea",
  user_token_element_id: "token_textarea",

  /// Extract users public key from the related textarea
  ///
  /// @return
  ///      public key as openpgp.key object
  getPublicKey: function()
  {
    var public_key_string = this.getPublicKeyString();
    if (public_key_string === null) {
      throw new Error("Couldn't read the public key input. Please reload page.");
    }

    var public_key = util.generateKeyFromString(public_key_string);
    if (public_key === null) {
      throw new Error("Could not generate public key. Please check your input.");
    }

    return public_key.keys[0];
  },

  /// Extracts users public key from textarea "public_key_textarea".
  ///
  /// @return
  ///      "public_key_textarea" value as {string} or null if the id is missing
  getPublicKeyString: function()
  {
    var content = util.getTextAreaContent(this.user_public_key_element_id);
    if (!util.isString(content)) {
      return null;
    }

    return content.trim();
  },

  /**
   * Extract users token from textarea "token_textarea"
   *
   * @return {MPI}
   *    token extracted from input
   */
  getToken: function()
  {
    var token_string = this.getTokenString();
    if (token_string === null) {
      throw new Error("Couldn't read the token input. Please reload page.");
    }

    var token = util.str2MPI(token_string);

    if (!util.isMPIProbablyPrime(token)) {
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
    var content = util.getTextAreaContent(this.user_token_element_id);
    if (!util.isString(content)) {
      return null;
    }

    return content.trim();
  },

  /// TODO
  getServerPublicKey: function()
  {
    var public_key_string = this.getServerPublicKeyString();
    if (!util.isString(public_key_string)) {
      throw new Error("Couldn't read servers public key. Please reload page.");
    }

    var public_key = util.generateKeyFromString(public_key_string);
    if (public_key === null) {
      throw new Error("Couldn't convert server public key. Please reload page.");
    }

    return public_key.keys[0];
  },

  /// TODO
  getServerPublicKeyString: function()
  {
    var element = document.getElementById(this.server_public_key_element_id);
    if (element === null) {
      return null;
    }

    return element.innerHTML.trim();
  },

  /// Extracts the public MPIs from the servers public key.
  collectPublicBlindingInformation: function()
  {
    var server_public_key = this.getServerPublicKey();
    var blinding_information = new BlindingInformation();
    blinding_information.fromKey(server_public_key);

    return blinding_information;
  }
};