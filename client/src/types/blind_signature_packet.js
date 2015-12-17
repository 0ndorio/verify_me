"use strict";

var kbpgp = require("kbpgp");
var Constants = kbpgp.const;

var sig = require("../../node_modules/kbpgp/lib/openpgp/packet/signature");
var pad = require("../../node_modules/kbpgp/lib/pad");

var util = require("../util");

/// TODO
/// @parameter {KeyManager} target_key
/// @parameter {KeyManager} sig_key
var BlindKeysigPacket = function(target_key, sig_key)
{
  var hashed_subpackets = [
    new sig.CreationTime(this.calculateRandomCreationDate(target_key)),
    new sig.PreferredHashAlgorithms([Constants.openpgp.hash_algorithms.SHA512])
  ];

  var unhashed_subpackets = [
      new sig.Issuer(sig_key.get_pgp_key_id())
  ];

  var ctor_args = {
    hashed_subpackets: hashed_subpackets,
    key: sig_key.get_primary_keypair(),
    key_id: sig_key.get_pgp_key_id(),
    unhashed_subpackets: unhashed_subpackets,
    type: Constants.openpgp.sig_types.persona,
    version: Constants.openpgp.versions.signature.V4
  };

  sig.Signature.call(this, ctor_args);
  this.target_key = target_key;

  this.prepare_raw_sig();
};

BlindKeysigPacket.prototype = Object.create(sig.Signature.prototype);

/// Create random creation time between key creation und expire date
/// @parameter {KeyManager} target_public_key
BlindKeysigPacket.prototype.calculateRandomCreationDate = function(target_key)
{
  if (!util.isOpenPGPKey(target_key)) {
    return false;
  }

  var lifespan = target_key.primary.lifespan;
  var key_expire = lifespan.expire_in;

  // if no expire date is available use maximum possible day in the future
  //    - 100,000,000 days measured relative to midnight at the beginning of 01 January, 1970 UTC.
  //      http://es5.github.io/#x15.9.1.1
  if (null === key_expire || 0 >= key_expire) {
    key_expire = 8640000000000000;
  }

  return Math.floor(lifespan.generated + Math.random() * (key_expire - lifespan.generated));
};

/// TODO
BlindKeysigPacket.prototype.prepare_raw_sig = function()
{
  // TODO: Input Checks

  var signData = this.generate_sig_payload();
  var hashed_signData = this.hasher(signData);
  var target_length = this.key.pub.n.mpi_byte_length();

  this.raw_signature = pad.emsa_pkcs1_encode(
    hashed_signData, target_length, { hasher: this.hasher }
  );

  this.signed_hash_value_hash = this.raw_signature.toBuffer().slice(0, 2);
};

/// <signData>   = <pubKeyData> <userIdData> <sigData>
BlindKeysigPacket.prototype.generate_sig_payload = function()
{
  // <userIdData> = %xb4 <userIdLen> <userIdPacket>
  // <userIdLen>  = 4<OCTET> ; len(<userIdPacket >)
  var user_id_packet = this.target_key.get_userids_mark_primary()[0];
  var userIdData = user_id_packet.to_signature_payload();

  // <pubKeyData> = %x99 <pubKeyLen> <publicKeyPacket>
  // <pubKeyLen>  = 2<OCTET> ; len(<publicKeyPacket>)
  var key_material_packet = this.target_key.pgp.key(this.target_key.pgp.primary);
  var pubKeyData = key_material_packet.to_signature_payload();

  return kbpgp.Buffer.concat([
    pubKeyData, userIdData, this.generate_sig_data()
  ]);
};

/// <sigData>  = <sigHashdData> <sigTrailer>
BlindKeysigPacket.prototype.generate_sig_data = function()
{
  var sigHashData = this.generate_sig_prefix();
  var sigTrailer = this.generate_sig_trailer(sigHashData.length);

  return Buffer.concat([sigHashData, sigTrailer]);
};

/// <sigTrailer>     = %x04 %xff <sigHashDataLen>
/// <sigHashDataLen> = 4<OCTET> ; len(<sigHashData>)
BlindKeysigPacket.prototype.generate_sig_trailer = function(hash_data_length)
{
  return kbpgp.Buffer.concat([
    new kbpgp.Buffer([
      this.version,
      0xff
    ]),
    kbpgp.util.uint_to_buffer(32, hash_data_length)
  ]);
};

/// <sigHashData> = <version> <sigType> <pubAlgorithm>
///                 <hashAlgorithm> <hashedSubpktsLen>
///                 <hashedSubpkts>
BlindKeysigPacket.prototype.generate_sig_prefix = function()
{
  // <subpackets> = *<subpacket>
  var hashedSubpkts = this.hashed_subpackets
    .reduce(function(lhs, rhs) {
      return kbpgp.Buffer.concat([lhs.to_buffer(), rhs.to_buffer()]);
    });

  // <version>          = <OCTET>
  // <sigType>          = <OCTET>
  // <pubAlgorithm>     = <OCTET>
  // <hashAlgorithm>    = <OCTET>
  // <hashedSubpktsLen> = 2<OCTET> ; len(<hashedSubpkts>)
  // <hashedSubpkts>    = 1*<subpacket>
  return kbpgp.Buffer.concat([
    new Buffer([
      this.version,
      this.type,
      this.key.type,
      this.hasher.type
    ]),
    kbpgp.util.uint_to_buffer(16, hashedSubpkts.length),
    hashedSubpkts
  ]);
};

module.exports = BlindKeysigPacket;
