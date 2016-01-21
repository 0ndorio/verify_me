"use strict";

import * as kbpgp from "kbpgp"
const Constants = kbpgp.const;

import { assert, Buffer, check } from "verifyme_utility"
import * as sig from "../../node_modules/kbpgp/lib/openpgp/packet/signature"

import BlindingContext from "./../blinding/blinding_context"

/**
 * A kind of key signature packet where the signer
 * does not know whose key is signed.
 */
export default class BlindSignaturePacket extends sig.Signature
{
  /**
   * Creates a new signature packet.
   *
   * To avoid that the signer later finds a relationship between the
   * signature request and the published signature the signature creation
   * time is randomized.
   *
   * @param {KeyManager} target_key
   *    The key to sign stored in a {KeyManger}.
   * @param {KeyManager} sig_key
   *    The signers public key stored in a {KeyManger}.
   * @param {BlindingContext} context
   *    An algorithm based signing context to encode the prepared
   *    raw signature data.
   */
  constructor(target_key, sig_key, context)
  {
    assert(check.isKeyManager(target_key));
    assert(check.isKeyManager(sig_key));
    assert(context instanceof BlindingContext);

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

    this.prepareRawSignature(context);
  }

  /**
   * Calculates a random creation time between the given keys creation und expire date.
   * If no expire date exists, the maximum possible date value is used.
   *
   * @param {KeyManager} target_key
   *    The key we use as to identify the lifespan.
   * @returns {number}
   *    A random integer number somewhere in the given keys lifespan.
   */
  static calculateRandomCreationDate(target_key)
  {
    assert(check.isKeyManager(target_key));

    const lifespan = target_key.primary.lifespan;
    let key_expire = lifespan.expire_in;

    // if no expire date is available use maximum possible date in the future (8640000000000000)
    //    - 100,000,000 days measured relative to midnight at the beginning of 01 January, 1970 UTC.
    //      http://es5.github.io/#x15.9.1.1

    // pgp defines Time files as four-octet fields containing the number of seconds elapsed since 1/1/1970
    // so we have to use a smaller number (2^32 - 1)
    //    - https://tools.ietf.org/html/rfc4880#section-3.5
    if (null === key_expire || 0 >= key_expire) {
      key_expire = Math.pow(2, 32) - lifespan.generated - 1;
    }

    return Math.floor(lifespan.generated + Math.random() * key_expire);
  }

  /**
   * Prepares the raw signature data.
   *
   * This data is unsigned and encoded for the blind sign process
   * where the given blinding context is used. To finalize the
   * signature data the related blind signature algorithm must be used.
   *
   * @param {BlindingContext} context
   *    This context should be created from the signers public key and
   *    is used to encode the data in preparation of the signing algorithm.
   */
  prepareRawSignature(context)
  {
    assert(context instanceof BlindingContext);

    const signData = this.generateSignaturePayload();

    this.raw_signature = context.encodeSignaturePayload(signData, this.hasher);
    this.signed_hash_value_hash = this.raw_signature.toBuffer().slice(0, 2);
  }

  /**
   * Generates the unsigned key signature payload.
   *
   *  # RFC 4880 - 5.2.3.  Version 4 Signature Packet Format
   *  # RFC 4880 - 5.2.4.  Computing Signatures
   *
   * @returns {Buffer}
   *    The raw unsinged signature data.
   */
  generateSignaturePayload()
  {
    const key_material_packet = this.target_key.pgp.key(this.target_key.pgp.primary);
    const pubKeyData = key_material_packet.to_signature_payload();

    const user_id_packet = this.target_key.get_userids_mark_primary()[0];
    const userIdData = user_id_packet.to_signature_payload();

    return Buffer.concat([
      pubKeyData, userIdData, this.generateSignatureData()
    ]);
  }

  /**
   * Generates the complete public signature packet information.
   * These information are part of the final signature hash but
   * they become also part of the unhashed part of the final signature
   * packet.
   *
   *  @see generateSignatureBody()
   *  @see generateSignatureTrailer()
   *
   * @returns {Buffer}
   *    Public signature packet information.
   */
  generateSignatureData()
  {
    const sigBody = this.generateSignatureBody();
    const sigTrailer = this.generateSignatureTrailer(sigBody.length);

    return Buffer.concat([sigBody, sigTrailer]);
  }

  /**
   * Signature trailer of six octets.
   *
   * # RFC 4880 - 5.2.4.  Computing Signatures
   *
   *  - version of signature packet (1 octet)
   *  - 0xFF (1 octet)
   *  - length of hashed data without trailer (4 octet big-endian)
   *
   * @param {number} hash_data_length
   *    The total length of the signature data.
   * @returns {Buffer}
   *    The signature trailer.
   */
  generateSignatureTrailer(hash_data_length)
  {
    assert(check.isInteger(hash_data_length));

    return Buffer.concat([
      new Buffer([
        this.version,
        0xff
      ]),
      kbpgp.util.uint_to_buffer(32, hash_data_length)
    ]);
  }

  /**
   * Prepares the part of the signature body that gets hashed.
   *
   * # RFC 4880 - 5.2.3.  Version 4 Signature Packet Format
   * # RFC 4880 - 5.2.4.  Computing Signatures
   *
   *  - version of signature packet (1 octet)
   *  - signature type (1 octet)
   *  - public key algorithm (1 octet)
   *  - hash algorithm (1 octet)
   *  - total length of hashed subpackets (2 octet)
   *  - hashed subpackets data (zero or more packets)
   *
   * @returns {Buffer}
   *    Part of the signature body to hash.
   */
  generateSignatureBody()
  {
    const hashedSubpkts = this.hashed_subpackets
      .map(subpacket => subpacket.to_buffer())
      .reduce((lhs, rhs) => Buffer.concat([lhs, rhs]));

    return Buffer.concat([
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

  /**
   * Generates the complete signed signature packet payload.
   *
   * # RFC 4880 - 5.2.4.  Computing Signatures
   *
   *  - signature body to hash (@see generateSignatureBody())
   *  - length of unhashed subpackets (2 octet)
   *  - unhashed subpackets (zero or more)
   *  - left 16 bits of the signed hash value (2 octet)
   *  - signed hash (one or more MPI)
   *
   * @returns {Buffer}
   *    The signed signature packet payload.
   *
   * #
   * # keep naming to overwrite Signature.write_unframed()
   * #
   */
  write_unframed()
  {
    const unhashed_packet_data = this.unhashed_subpackets.reduce(
      (prevValue, subpacket) => { return Buffer.concat([prevValue, subpacket.to_buffer()])},
      new Buffer({})
    );

    return Buffer.concat([
      this.generateSignatureBody(),
      kbpgp.util.uint_to_buffer(16, unhashed_packet_data.length),
      unhashed_packet_data,
      this.signed_hash_value_hash,
      this.sig
    ]);
  }
}
