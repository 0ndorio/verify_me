define(function(require) {

   'use strict';

   var util = require('./util');

   /// TODO
   function blind_message(message_as_string, blinding_information)
   {
      var message_as_MPI = util.str2MPI(message_as_string);

      var m = message_as_MPI.data;
      var r = blinding_information.blinding_factor;
      var e = blinding_information.public_exponent;
      var N = blinding_information.modulus;

      return m.multiply(r.modPow(e, N));
   }

   /// TODO
   function unblind_message(message_as_mpi, blinding_information)
   {
      var N = blinding_information.modulus;
      var r = blinding_information.blinding_factor;

      var r_inv = r.modInverse(N);

      var m = message_as_mpi;

      return m.multiply(r_inv);
   }

   return {
      blind_message:    blind_message,
      unblind_message:  unblind_message
   };
});