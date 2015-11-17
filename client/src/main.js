"use strict";

var blinding = require("./blinding");
var client = require("./client");
var util = require("./util");


//------------------------------


var openpgp = require("openpgp");

function prepareBlindSignature()
{
  var server_public_key = client.getServerPublicKey();
  var server_public_key_packet = server_public_key.primaryKey;

  var signature_packet = new openpgp.packet.Signature();
  //signature_packet.signatureType = openpgp.enums.signature.key;
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

  // reduce target size by two to allow mpi header bytes to be enclosed
  //var target_length = (server_public_key_packet.getBitSize() / 8) - 2;
  //var hashed_sign_data = openpgp.crypto.pkcs1.emsa.encode(signature_packet.hashAlgorithm, sign_data, target_length);
  //var hashed_sign_data_string = hashed_sign_data.toMPI();

  var target_length = (server_public_key_packet.getBitSize() / 8);
  var hashed_sign_data = openpgp.crypto.pkcs1.emsa.encode(signature_packet.hashAlgorithm, sign_data, target_length);
  var hashed_sign_data_string = util.bigInt2Bytes(hashed_sign_data);

  signature_packet.signedHashValue = hashed_sign_data_string.substr(0, 2);

  return {
    "signature_packet": signature_packet,
    "message": hashed_sign_data_string
  };
}


//------------------------------


function checkResult(unblinded_message, blinding_information)
{
  console.log('Signed Message:');
  console.log('---------------');
  console.log(util.bigInt2Bytes(unblinded_message)+'\n\n');

  var e = blinding_information.public_exponent;
  var N = blinding_information.modulus;
  var m = unblinded_message.modPow(e, N);

  console.log('Original Message:');
  console.log('-----------------');
  console.log(util.bigInt2Bytes(m));
}

function serverRequest(blinded_message, blinding_information)
{
  return new Promise(function(resolve, reject) {

    var xhttp = new XMLHttpRequest();
    xhttp.open("POST", "/");
    xhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");

    xhttp.onload = function () {
      if (xhttp.readyState === 4 && xhttp.status === 200) {
        resolve(xhttp.responseText);
      } else {
        reject(new Error(xhttp.statusText));
      }
    };

    xhttp.onerror = function() {
      reject(new Error("Network Error"));
    };

    xhttp.send(JSON.stringify({
      message: blinded_message,
      token_hash: blinding_information.hashed_token.toString(16)
    }));
  });
}

/// TODO
function requestPseudonym()
{
  /// blinding factor and modulus must be coprime
  ///   - ensured through the use of prime numbers
  ///   - blinding factor is generated through the multiplication of prime token and two additional prime numbers
  /// blinding factor must be smaller than Modulus
  ///   - number of bits after multiplication of two numbers with the same bit length (n) is 2n or less
  ///     (https://math.stackexchange.com/questions/682618/the-maximum-number-of-digits-in-binary-multiplication)
  ///   - TODO: unsure how to handle this properly
  var blinding_information = client.collectPublicBlindingInformation();
  var prime_bit_length = Math.floor(blinding_information.modulus.bitLength() / 4);

  var blind_signature = prepareBlindSignature();

  util.generateTwoPrimeNumbers(prime_bit_length).then(function(primes) {

    var token = client.getToken();

    blinding_information.hashed_token = util.bytes2MPI(util.hashMessage(token.data.toRadix())).data;
    blinding_information.blinding_factor = token.data.multiply(primes[0].multiply(primes[1]));

    /// TODO: workaround for unhandled length problem ... if blinding factor is to large this reduces its size
    if (blinding_information.blinding_factor.compareTo(blinding_information.modulus) > 0) {
      blinding_information.blinding_factor = token.data.multiply(primes[0]);
    }

    return blinding.blind_message(blind_signature.message, blinding_information).toRadix();
  })
  .then(function(blinded_message) {
    return serverRequest(blinded_message, blinding_information);
  })
  .then(function(signed_blinded_message) {
    var unblinded_message = blinding.unblind_message(signed_blinded_message, blinding_information);

    var signature_packet = blind_signature.signature_packet;
    signature_packet.signature = unblinded_message.toMPI();

    var verify_me = new openpgp.packet.Literal();
    verify_me.setBytes(signature_packet.signature, 'binary');

    var public_key = client.getPublicKey();
    var result = signature_packet.verify(client.getServerPublicKey().primaryKey, {
      key: public_key.primaryKey,
      userid: public_key.getPrimaryUser().user.userId
    });

    console.log("Signature veryfied: " + result);

    /// DUMP
    var public_key = client.getPublicKey();
    var user = public_key.getPrimaryUser().user;
    if (!user.otherCertifications) { user.otherCertifications = [] };
    user.otherCertifications.push(signature_packet);
    //var packet_list = new openpgp.packet.List();
    //packet_list.push(signature_packet);
    //public_key.packetlist2structure(packet_list);
    console.log(public_key.armor());
  });
}

document.getElementById("activate_pseudonym_button").onclick = requestPseudonym;