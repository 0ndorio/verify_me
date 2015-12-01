"use strict";

var openpgp = require("openpgp");
var util = require("../util");

var BlindKeySignaturePacket = function()
{
  openpgp.packet.Signature.call(this);
  this.signatureType = openpgp.enums.signature.cert_generic;
};

BlindKeySignaturePacket.prototype = Object.create(openpgp.packet.Signature.prototype);

BlindKeySignaturePacket.prototype.configure = function(target_public_key, signer_public_key)
{
  if (!util.isOpenPGPKey(target_public_key) || !util.isOpenPGPKey(signer_public_key)) {
    return null;
  }

  var success = true;
  success &= this.extractSignersPublicInformation(target_public_key);
  success &= this.calculateRandomCreationDate(target_public_key);
  success &= this.calculateSignatureData();
  success &= this.calculateSignatureHash(target_public_key, signer_public_key);

  return success;
}

BlindKeySignaturePacket.prototype.extractSignersPublicInformation = function(signer_public_key)
{
  if (!util.isOpenPGPKey(signer_public_key)) {
    return false;
  }

  var signer_public_key_packet = signer_public_key.primaryKey;

  this.hashAlgorithm = signer_public_key.getPreferredHashAlgorithm();
  this.issuerKeyId = signer_public_key_packet.getKeyId();
  this.publicKeyAlgorithm = openpgp.enums.write(openpgp.enums.publicKey, signer_public_key_packet.algorithm);

  return true;
};

// prepare sign data (@see Timo Engel thesis)
//
// <signatureData>  = <sigHashdData> <sigTrailer >
// <sigHashData>    = <version> <signatureType> <pubAlgorithm>
//                    <hashAlgorithm> <hashedSubpktsLen>
//                    <hashedSubpkts>
// <sigTrailer>     = %x04 %xff <sigHashDataLen>
// <sigHashDataLen> = 4<OCTET>
BlindKeySignaturePacket.prototype.calculateSignatureData = function()
{
  if (!this.containsInformationToCreateSignDataField()) {
    return false;
  }

  var sig_hash_data_string = String.fromCharCode(this.version);
  sig_hash_data_string += String.fromCharCode(this.signatureType);
  sig_hash_data_string += String.fromCharCode(this.publicKeyAlgorithm);
  sig_hash_data_string += String.fromCharCode(this.hashAlgorithm);
  sig_hash_data_string += this.write_all_sub_packets();

  this.signatureData = sig_hash_data_string;

  return true;
};

/// TODO
BlindKeySignaturePacket.prototype.containsInformationToCreateSignDataField = function()
{
  return util.isInteger(this.version)
      && util.isInteger(this.signatureType)
      && util.isInteger(this.publicKeyAlgorithm)
      && util.isInteger(this.hashAlgorithm);
};

// Create random creation time between key creation und expire date
// if no expire date is available use maximum possible day in the future
//    - 100,000,000 days measured relative to midnight at the beginning of 01 January, 1970 UTC.
//      http://es5.github.io/#x15.9.1.1
//
BlindKeySignaturePacket.prototype.calculateRandomCreationDate = function(target_public_key)
{
  if (!util.isOpenPGPKey(target_public_key)) {
    return false;
  }

  var key_expire = target_public_key.getExpirationTime();
  if (null === key_expire || 0 === key_expire.getTime()) {
    key_expire = 8640000000000000;
  } else {
    key_expire = key_expire.getTime();
  }

  var public_key_packet = target_public_key.primaryKey;
  var key_created = public_key_packet.created.getTime();

  var signature_created = Math.floor(key_created + Math.random() * (key_expire - key_created));
  this.created = new Date(signature_created);

  return (this.created instanceof Date);
};

// prepare sign data (@see Timo Engel thesis)
//
// <signData>   = <pubKeyData> <userIdData> <signatureData>
// <userIdData> = %xb4 <userIdLen> <userIdPacket>
// <userIdLen>  = 4<OCTET> ; len(<userIdPacket >)
// <pubKeyData> = %x99 <pubKeyLen> <publicKeyPacket>
// <pubKeyLen>  = 2<OCTET> ; len(<publicKeyP
BlindKeySignaturePacket.prototype.calculateSignatureHash = function (target_public_key, signer_public_key)
{
  if (!this.containsInformationToCreateSignatureHash()
    || !util.isOpenPGPKey(target_public_key)
    || !util.isOpenPGPKey(signer_public_key)) {

    return false;
  }

  var hashed_sign_data = this.generateHashedSignData(target_public_key, signer_public_key);
  if (null === hashed_sign_data) {
    return false;
  }

  this.unsigned_signature = util.bigInt2Bytes(hashed_sign_data);
  this.signedHashValue = this.unsigned_signature.substr(0, 2);

  return true;
};

/// TODO
BlindKeySignaturePacket.prototype.containsInformationToCreateSignatureHash = function()
{
  return this.containsInformationToCreateSignDataField()
      && util.isInteger(this.hashAlgorithm);
};

/// TODO
BlindKeySignaturePacket.prototype.getUserIDDataFromKey = function(target_public_key)
{
  if (!util.isOpenPGPKey(target_public_key)) {
    return null;
  }

  var user = target_public_key.getPrimaryUser().user;
  var user_id_packet_string = user.userId.write();
  return "\u00B4" + openpgp.util.writeNumber(user_id_packet_string.length, 4) + user_id_packet_string;
};

/// TODO
BlindKeySignaturePacket.prototype.generateHashedSignData = function(target_public_key, signer_public_key)
{
  if (!util.isOpenPGPKey(target_public_key) || !util.isOpenPGPKey(signer_public_key)) {
    return null;
  }

  var public_key_data = target_public_key.primaryKey.writeOld();
  var user_id_data = this.getUserIDDataFromKey(target_public_key);

  var sign_data = public_key_data + user_id_data + this.signatureData + this.calculateTrailer();
  var target_length = (signer_public_key.primaryKey.getBitSize() / 8);

  return openpgp.crypto.pkcs1.emsa.encode(this.hashAlgorithm, sign_data, target_length);
};

module.exports = BlindKeySignaturePacket;
