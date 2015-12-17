"use strict";

var BlindingInformation = require("./types/blinding_information");
var blinding = require("./blinding");
var client = require("./client");
var util = require("./util");

var kbpgp = require("kbpgp");

function export_keys_to_binary_and_inject_signature(keymanager,  signature, opts)
{
  var pgpengine = keymanager.pgp;
  var primary_userid = keymanager.get_userids_mark_primary()[0];

  var packets = [pgpengine.key(pgpengine.primary).export_framed(opts)];
  pgpengine.userids.forEach(function(userid) {
    packets.push(userid.write(), userid.get_framed_signature_output());

    if (primary_userid === userid) {
      packets.push(signature.get_framed_output());
    }
  });

  opts.subkey = true;

  pgpengine.subkeys.forEach(function(subkey) {
    var material = pgpengine.key(subkey);
    packets.push(material.export_framed(opts), material.get_subkey_binding_signature_output());
  });

  kbpgp.util.assert_no_nulls(packets);
  return kbpgp.Buffer.concat(packets);
}

/// TODO
function requestPseudonym()
{
  var blind_signature_packet = blinding.prepareBlindSignature();
  var token = client.getToken();

  /// blinding factor and modulus must be coprime
  ///   - ensured through the use of prime numbers
  ///   - blinding factor is generated through the multiplication of prime token and two additional prime numbers
  /// blinding factor must be smaller than Modulus
  ///   - number of bits after multiplication of two numbers with the same bit length (n) is 2n or less
  ///     (https://math.stackexchange.com/questions/682618/the-maximum-number-of-digits-in-binary-multiplication)
  ///   - TODO: unsure how to handle this properly
  var blinding_information = client.collectPublicBlindingInformation();
  //var prime_bit_length = Math.floor((blinding_information.modulus.bitLength() - token.data.bitLength() - 1) / 2);

  return util.generateTwoPrimeNumbers(128)
    .then(function (primes) {

      blinding_information.hashed_token = util.bytes2MPI(util.hashMessage(token.data.toRadix())).data;
      blinding_information.blinding_factor = token.data.multiply(primes[0].multiply(primes[1]));

      /// TODO: workaround for unhandled length problem ... if blinding factor is to large this reduces its size
      if (blinding_information.blinding_factor.compareTo(blinding_information.modulus) > 0) {
        blinding_information.blinding_factor = token.data.multiply(primes[0]);
      }

      return blinding.blind_message(blind_signature_packet.raw_signature, blinding_information).toRadix();
    })
    .then(function (blinded_message) {
      return client.sendBlindingRequest(blinded_message, blinding_information);
    })
    .then(function (signed_blinded_message) {

      var message = new util.BigInteger(signed_blinded_message, 10);

      var unblinded_message = blinding.unblind_message(message, blinding_information);
      if (null === unblinded_message) {
        throw new Error("Could not unblind the signed blinded message");
      }

      var target_key = client.getPublicKey();

      /// ---------------------------------------
      /// Inject Signed Data

      blind_signature_packet.sig = unblinded_message.to_mpi_buffer();

      /// ---------------------------------------
      /// Calculate Unframed Signature Body

      var unhashed_packet_data = new kbpgp.Buffer({});
      blind_signature_packet.unhashed_subpackets.forEach(function (packet) {
        unhashed_packet_data = kbpgp.Buffer.concat([unhashed_packet_data, packet.to_buffer()]);
      });

      var unframed_sig = kbpgp.Buffer.concat([
        blind_signature_packet.generate_sig_prefix(),
        kbpgp.util.uint_to_buffer(16, unhashed_packet_data.length),
        unhashed_packet_data,
        blind_signature_packet.signed_hash_value_hash,
        blind_signature_packet.sig
      ]);

      /// ---------------------------------------
      /// Calculate & Inject Framed Signature Body

      var framed_sig = blind_signature_packet.frame_packet(kbpgp.const.openpgp.packet_tags.signature, unframed_sig);
      blind_signature_packet._framed_output = framed_sig;

      /// ---------------------------------------
      /// Veryfication & Export

      var key_material_packet = target_key.pgp.key(target_key.pgp.primary);
      blind_signature_packet.primary = key_material_packet;

      blind_signature_packet.verify(
        [target_key.get_userids_mark_primary()[0]],
        function(err) {
          if (null !== err) {
            console.log("Error during final signature verification. Please restart the process.");
            console.log(err);
          }

          var key_binary = export_keys_to_binary_and_inject_signature(target_key, blind_signature_packet, {});
          var key_ascii = kbpgp.armor.encode(kbpgp.const.openpgp.message_types.public_key, key_binary);

          console.log(key_ascii);
        }

        /// ---------------------------------------
      );
    })
    .catch(function(error) {console.log(error); });
}

// TODO: refactoring necessary
// set request button active
if (typeof document !== "undefined" && document.getElementById("activate_pseudonym_button")) {
  document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;
}

// exports requestPseudonym to allow testing
if(typeof exports !== 'undefined') {
  exports.requestPseudonym = requestPseudonym;
}
