"use strict";

var util = require("./util");

module.exports = {

  /// TODO
  blind_message: function(message_as_string, blinding_information)
  {
    if (!util.isString(message_as_string) || !util.isFullValidBlindingInformation(blinding_information)) {
      return null;
    }

    var message_as_MPI = util.str2MPI(message_as_string);
    if (!util.isMPIWithData(message_as_MPI)) {
      return null;
    }

    var m = message_as_MPI.data;
    var r = blinding_information.blinding_factor;
    var e = blinding_information.public_exponent;
    var N = blinding_information.modulus;

    return m.multiply(r.modPow(e, N));
  },

  /// TODO
  unblind_message: function(message_as_mpi, blinding_information)
  {
    if (!util.isMPIWithData(message_as_mpi) || !util.isFullValidBlindingInformation(blinding_information)) {
      return null;
    }

    var N = blinding_information.modulus;
    var r = blinding_information.blinding_factor;

    var r_inv = r.modInverse(N);
    var m = message_as_mpi;

    return m.multiply(r_inv);
  }
};