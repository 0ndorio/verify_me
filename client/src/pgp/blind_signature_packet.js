"use strict";

import * as kbpgp from "kbpgp"
import * as sig from "../../node_modules/kbpgp/lib/openpgp/packet/signature"
const Constants = kbpgp.const;

import BlindingContext from "./../blinding/blinding_context"
import * as util from "../util"

/// TODO
export default class BlindSignaturePacket extends sig.Signature
{
  /// TODO
  constructor(target_key, sig_key, context)
  {
    const hashed_subpackets = [
      new sig.CreationTime(BlindSignaturePacket.calculateRandomCreationDate(target_key))
    ];

    const unhashed_subpackets = [
      new sig.Issuer(sig_key.get_pgp_key_id())
    ];

    const ctor_args = {
      hashed_subpackets: hashed_subpackets,
      key: sig_key.get_primary_keypair(),
      key_id: sig_key.get_pgp_key_id(),
      unhashed_subpackets: unhashed_subpackets,
      type: Constants.openpgp.sig_types.persona,
      version: Constants.openpgp.versions.signature.V4
    };

    super(ctor_args);

    this.tag = kbpgp.const.openpgp.packet_tags.signature;
    this.target_key = target_key;
    this.primary = target_key.pgp.key(target_key.pgp.primary);

    this.prepare_raw_sig(context);
  }

  /// Create random creation time between key creation und expire date
  /// @parameter {KeyManager} target_public_key
  static calculateRandomCreationDate(target_key)
  {
    if (!util.isKeyManager(target_key)) {
      return false;
    }

    const lifespan = target_key.primary.lifespan;
    let key_expire = lifespan.expire_in;

    // if no expire date is available use maximum possible date in the future (8640000000000000)
    //    - 100,000,000 days measured relative to midnight at the beginning of 01 January, 1970 UTC.
    //      http://es5.github.io/#x15.9.1.1

    // pgp defines Time files as four-octet fields containing the number of seconds elapsed since 1/1/1970
    // so we have to use a smaller number (2^32 - 1)
    //    - https://tools.ietf.org/html/rfc4880#section-3.5
    if (null === key_expire || 0 >= key_expire) {
      key_expire = Math.pow(2, 32) - 1;
    }

    return Math.floor(lifespan.generated + Math.random() * (key_expire - lifespan.generated));
  }

  /// TODO
  prepare_raw_sig(context)
  {
    const signData = this.generate_sig_payload();

    this.raw_signature = context.encode_signature_data(signData, this.hasher);
    this.signed_hash_value_hash = this.raw_signature.toBuffer().slice(0, 2);
  }

  /// TODO
  generate_sig_payload()
  {
    const key_material_packet = this.target_key.pgp.key(this.target_key.pgp.primary);
    const pubKeyData = key_material_packet.to_signature_payload();

    const user_id_packet = this.target_key.get_userids_mark_primary()[0];
    const userIdData = user_id_packet.to_signature_payload();

    return kbpgp.Buffer.concat([
      pubKeyData, userIdData, this.generate_sig_data()
    ]);
  }

  /// TODO
  generate_sig_data()
  {
    const sigHashData = this.generate_sig_prefix();
    const sigTrailer = this.generate_sig_trailer(sigHashData.length);

    return Buffer.concat([sigHashData, sigTrailer]);
  }

  /// TODO
  generate_sig_trailer(hash_data_length)
  {
    return kbpgp.Buffer.concat([
      new kbpgp.Buffer([
        this.version,
        0xff
      ]),
      kbpgp.util.uint_to_buffer(32, hash_data_length)
    ]);
  }

  /// TODO
  generate_sig_prefix()
  {
    const hashedSubpkts = this.hashed_subpackets
      .map(subpacket => subpacket.to_buffer())
      .reduce((lhs, rhs) => kbpgp.Buffer.concat([lhs, rhs]));

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
  }

  /// Calculate & inject framed signature body
  write()
  {
    const unframed_sig = this.write_unframed();
    this._framed_output = this.frame_packet(this.tag, unframed_sig);

    return this._framed_output;
  }

  /// Calculate unframed signature body
  write_unframed()
  {
    const unhashed_packet_data = this.unhashed_subpackets.reduce(
      (prevValue, subpacket) => { return kbpgp.Buffer.concat([prevValue, subpacket.to_buffer()])},
      new kbpgp.Buffer({})
    );

    return kbpgp.Buffer.concat([
      this.generate_sig_prefix(),
      kbpgp.util.uint_to_buffer(16, unhashed_packet_data.length),
      unhashed_packet_data,
      this.signed_hash_value_hash,
      this.sig
    ]);
  }
}