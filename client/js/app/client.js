define(function(require) {

   var util = require('./util');

   /// Extract users public key from the related textarea
   ///
   /// @return
   ///      public key as openpgp.key object
   function getPublicKey()
   {
      var public_key_string = getPublicKeyString();
      if (public_key_string === null) { return null; }

      var public_key = util.generateKeyFromString(public_key_string);
      if (public_key === null) {
         throw new Error("Could not generate public key. Please check your input.");
      }

      return public_key.keys[0];
   }

   /// Extracts users public key from textarea "public_key_textarea".
   ///
   /// @return
   ///      "public_key_textarea" value as {string}
   function getPublicKeyString()
   {
      var textarea_name = "public_key_textarea";
      return util.getTextAreaContent(textarea_name);
   }

   /// Extract users token from textarea "token_textarea"
   ///
   /// @return
   ///   token as openpgp.MPI
   function getToken()
   {
      var token_string = getTokenString();
      if (token_string === null) { return null; }

      var token = util.str2MPI(token_string);

      if (!util.isMPIProbablyPrime(token)) {
         throw new Error("Unsecure Token. Please check your input.");
      }

      return token;
   }

   /// Extracts users token from textarea "token_textarea".
   ///
   /// @return
   ///      "token_textarea" value as {string}
   function getTokenString()
   {
      var textarea_name = "token_textarea";
      return util.getTextAreaContent(textarea_name);
   }

   /// TODO
   function getServerPublicKey()
   {
      var public_key_string = SERVER_PUBLIC_KEY_STRING();
      var public_key = util.generateKeyFromString(public_key_string);

      if (public_key === null) {
         throw new Error("Could not read servers public key. Please reload page.");
      }

      return public_key.keys[0];
   }

   /// Extracts the public MPIs from the servers public key.
   function collectPublicBlindingInformation()
   {
      var server_public_key = getServerPublicKey();

      return {
         modulus:          server_public_key.primaryKey.mpi[0].data,
         public_exponent:  server_public_key.primaryKey.mpi[1].data,
      }
   }

   return {
      collectPublicBlindingInformation:   collectPublicBlindingInformation,

      getPublicKey:        getPublicKey,
      getPublicKeyString:  getPublicKeyString,

      getServerPublicKey:  getServerPublicKey,

      getToken:         getToken,
      getTokenString:   getTokenString
   };
});