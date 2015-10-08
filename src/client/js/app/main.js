define(function (require) {

   var blinding = require('./blinding');
   var client = require('./client');
   var util = require('./util');

   document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;

   /// TODO
   function requestPseudonym()
   {
      var blinding_information = client.collectPublicBlindingInformation();

      util.generatePrimeNumber(1024).then(function(prime) {

         var token = client.getToken();
         blinding_information.blinding_factor = token.data.multiply(prime);

         var public_key_string = client.getPublicKeyString();
         var hashed_message = util.hashMessage(public_key_string);

         return blinding.blind_message(hashed_message, blinding_information);
      })
      .then(function(blinded_message) {

         return dummyServerRequest(blinded_message, blinding_information);
      })
      .then(function(signed_blinded_message) {

         return blinding.unblind_message(signed_blinded_message, blinding_information);
      })
      .then(function(unblinded_message) {

         console.log('Signed Message:');
         console.log('---------------');
         console.log(util.bigInt2str(unblinded_message)+'\n\n');

         var e = blinding_information.public_exponent;
         var N = blinding_information.modulus;
         var m = unblinded_message.modPow(e, N);

         console.log('Original Message:');
         console.log('-----------------');
         console.log(util.bigInt2str(m));
      });
   }

   /// Dummy for a synchronous xmlhttprequest
   function dummyServerRequest(blinded_message, blinding_information)
   {
      var dummyPrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: GPGTools - https://gpgtools.org\n\n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\nzkYkIKmS+MmcRNWl\n=mox4\n-----END PGP PRIVATE KEY BLOCK-----";
      /// ---------------------------
      /// Dummy server communication
      var signed_blinded_message = function(blinded_message) {
         var target_secret_key_string = dummyPrivateKey;
         var target_secret_key = util.generateKeyFromString(target_secret_key_string).keys[0];
         var secret_exponent = target_secret_key.primaryKey.mpi[2];

         return blinded_message.modPow(secret_exponent.data, blinding_information.modulus);
      }(blinded_message);
      /// ---------------------------

      return signed_blinded_message;
   }
});