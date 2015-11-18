"use strict";

var BlindingInformation = require("./types/blinding_information");
var client = require("./client");
var util = require("./util");

var openpgp = require("openpgp");

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
    if (!(util.isString(message) || /^[0-9]+$/.test(message))
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
    var server_public_key = client.getServerPublicKey();
    var server_public_key_packet = server_public_key.primaryKey;

    var signature_packet = new openpgp.packet.Signature();
    signature_packet.signatureType = openpgp.enums.signature.cert_generic;
    signature_packet.hashAlgorithm = server_public_key.getPreferredHashAlgorithm();
    signature_packet.issuerKeyId = server_public_key_packet.getKeyId();
    signature_packet.publicKeyAlgorithm = openpgp.enums.write(openpgp.enums.publicKey, server_public_key_packet.algorithm);

    //
    // Create random creation time between key creation und expire date
    // if no expire date is available use maximum possible day in the future
    //    - 100,000,000 days measured relative to midnight at the beginning of 01 January, 1970 UTC.
    //      http://es5.github.io/#x15.9.1.1
    //

    var public_key = client.getPublicKey();
    var public_key_packet = public_key.primaryKey;

    var key_created = public_key_packet.created.getTime();
    var key_expire = public_key.getExpirationTime();
    if (null === key_expire || 0 === key_expire.getTime()) {
      key_expire = 8640000000000000;
    } else {
      key_expire = key_expire.getTime();
    }

    var signature_created = Math.floor(key_created + Math.random() * (key_expire - key_created));
    signature_packet.created = new Date(signature_created);

    //
    // prepare sign data (@see Timo Engel thesis)
    //
    // <signatureData>  = <sigHashdData> <sigTrailer >
    // <sigHashData>    = <version> <signatureType> <pubAlgorithm>
    //                    <hashAlgorithm> <hashedSubpktsLen>
    //                    <hashedSubpkts>
    // <sigTrailer>     = %x04 %xff <sigHashDataLen>
    // <sigHashDataLen> = 4<OCTET>

    var sig_hash_data_string = String.fromCharCode(signature_packet.version);
    sig_hash_data_string += String.fromCharCode(signature_packet.signatureType);
    sig_hash_data_string += String.fromCharCode(signature_packet.publicKeyAlgorithm);
    sig_hash_data_string += String.fromCharCode(signature_packet.hashAlgorithm);
    sig_hash_data_string += signature_packet.write_all_sub_packets();

    signature_packet.signatureData = sig_hash_data_string;

    //
    // prepare sign data (@see Timo Engel thesis)
    //
    // <signData>   = <pubKeyData> <userIdData> <signatureData>
    // <userIdData> = %xb4 <userIdLen> <userIdPacket>
    // <userIdLen>  = 4<OCTET> ; len(<userIdPacket >)
    // <pubKeyData> = %x99 <pubKeyLen> <publicKeyPacket>
    // <pubKeyLen>  = 2<OCTET> ; len(<publicKeyP
    //

    var public_key_data = public_key_packet.writeOld();

    var user = public_key.getPrimaryUser().user;
    var user_id_packet_string = user.userId.write();
    var user_id_data = "\u00B4" + openpgp.util.writeNumber(user_id_packet_string.length, 4) + user_id_packet_string;

    var sign_data = public_key_data + user_id_data + signature_packet.signatureData + signature_packet.calculateTrailer();

    var target_length = (server_public_key_packet.getBitSize() / 8);
    var hashed_sign_data = openpgp.crypto.pkcs1.emsa.encode(signature_packet.hashAlgorithm, sign_data, target_length);
    var hashed_sign_data_string = util.bigInt2Bytes(hashed_sign_data);

    signature_packet.signedHashValue = hashed_sign_data_string.substr(0, 2);

    return {
      "signature_packet": signature_packet,
      "message": hashed_sign_data_string
    };
  }
};