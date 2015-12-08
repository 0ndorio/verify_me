"use strict";

var BlindingInformation = require("./types/blinding_information");
var BlindKeySignaturePacket = require("./types/blind_signature_packet");
var client = require("./client");
var util = require("./util");

module.exports = {

  /// TODO : Avoid blinding and encrpytion in one step!
  blind_message: function(message, blinding_information)
  {
    if (!(util.isString(message) || /^[0-9]+$/.test(message))
      || !BlindingInformation.isValidFullBlindingInformation(blinding_information)) {
      return null;
    }

    var message_as_MPI = util.bytes2MPI(message);

    var m = message_as_MPI.data;
    var r = blinding_information.blinding_factor;
    var e = blinding_information.public_exponent;
    var N = blinding_information.modulus;

    return m.multiply(r.modPow(e, N));
  },

  /// TODO
  unblind_message: function(message, blinding_information)
  {
    if (!(util.isString(message) && /^[0-9]+$/.test(message))
          || !BlindingInformation.isValidFullBlindingInformation(blinding_information)) {
      return null;
    }

    var m = util.str2BigInt(message);
    var N = blinding_information.modulus;
    var r = blinding_information.blinding_factor;

    var r_inv = r.modInverse(N);
    return m.multiply(r_inv);
  },

  /// TODO
  prepareBlindSignature: function ()
  {
    var public_key = client.getPublicKey();
    var server_public_key = client.getServerPublicKey();

    var signature_packet = new BlindKeySignaturePacket();
    if (!signature_packet.configure(public_key, server_public_key)) {
      signature_packet = null;
    }

    return signature_packet;
  }
};