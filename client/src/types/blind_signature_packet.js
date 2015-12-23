"use strict";

import * as kbpgp from "kbpgp"
var Constants = kbpgp.const;

import * as sig from "../../node_modules/kbpgp/lib/openpgp/packet/signature"
import * as pad from "../../node_modules/kbpgp/lib/pad"

import * as util from "../util"

/// TODO
/// @parameter {KeyManager} target_key
/// @parameter {KeyManager} sig_key
var BlindSignaturePacket = function(target_key, sig_key)
{
  this.target_key = target_key;
  this.primary = target_key.pgp.key(target_key.pgp.primary);

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
  this.prepare_raw_sig();
};

BlindSignaturePacket.prototype = Object.create(sig.Signature.prototype);
BlindSignaturePacket.prototype.tag = kbpgp.const.openpgp.packet_tags.signature;

/// Create random creation time between key creation und expire date
/// @parameter {KeyManager} target_public_key
BlindSignaturePacket.prototype.calculateRandomCreationDate = function(target_key)
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
BlindSignaturePacket.prototype.prepare_raw_sig = function()
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

BlindSignaturePacket.prototype.generate_sig_payload = function()
{
  var key_material_packet = this.target_key.pgp.key(this.target_key.pgp.primary);
  var pubKeyData = key_material_packet.to_signature_payload();

  var user_id_packet = this.target_key.get_userids_mark_primary()[0];
  var userIdData = user_id_packet.to_signature_payload();

  return kbpgp.Buffer.concat([
    pubKeyData, userIdData, this.generate_sig_data()
  ]);
};

BlindSignaturePacket.prototype.generate_sig_data = function()
{
  var sigHashData = this.generate_sig_prefix();
  var sigTrailer = this.generate_sig_trailer(sigHashData.length);

  return Buffer.concat([sigHashData, sigTrailer]);
};

BlindSignaturePacket.prototype.generate_sig_trailer = function(hash_data_length)
{
  return kbpgp.Buffer.concat([
    new kbpgp.Buffer([
      this.version,
      0xff
    ]),
    kbpgp.util.uint_to_buffer(32, hash_data_length)
  ]);
};

BlindSignaturePacket.prototype.generate_sig_prefix = function()
{
  var hashedSubpkts = this.hashed_subpackets
    .reduce(function(lhs, rhs) {
      return kbpgp.Buffer.concat([lhs.to_buffer(), rhs.to_buffer()]);
    });

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

/// Calculate & Inject Framed Signature Body
BlindSignaturePacket.prototype.write = function()
{
  var unframed_sig = this.write_unframed();
  this._framed_output = this.frame_packet(this.tag, unframed_sig);

  return this._framed_output;
};

/// Calculate Unframed Signature Body
BlindSignaturePacket.prototype.write_unframed = function()
{
  var unhashed_packet_data = new kbpgp.Buffer({});
  this.unhashed_subpackets.forEach(function (packet) {
    unhashed_packet_data = kbpgp.Buffer.concat([unhashed_packet_data, packet.to_buffer()]);
  });

  return kbpgp.Buffer.concat([
    this.generate_sig_prefix(),
    kbpgp.util.uint_to_buffer(16, unhashed_packet_data.length),
    unhashed_packet_data,
    this.signed_hash_value_hash,
    this.sig
  ]);
};

module.exports = BlindSignaturePacket;
