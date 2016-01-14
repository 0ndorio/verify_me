"use strict";

import * as kbpgp from "kbpgp"

import BlindSignaturePacket from "./blind_signature_packet"
import util from "../util"

/**
 * Exports the given public key (stored in a {KeyManager}) as binary data
 * and injects a given key signature packet directly behind the related userid.
 *
 * This is necessary because kbpgp does not support non self-signature signature
 * packets.
 *
 * @param {KeyManager} key_manager
 *    The public key to export.
 * @param {Signature} signature_packet
 *    The key signature to inject.
 * @param {object} opts
 *    Possibility to add additional options to pass
 *    to the kbpgp key export function.
 * @returns {Buffer}
 *    The public pgp key with additional injected signature
 *    as binary data.
 */
function export_keys_to_binary_and_inject_signature(key_manager, signature_packet, opts = {})
{
  assert(util.isKeyManager(key_manager));
  assert(signature_packet instanceof BlindSignaturePacket);
  assert(util.isObject(opts));

  const pgpengine = key_manager.pgp;
  const primary_userid = key_manager.get_userids_mark_primary()[0];

  let packets = [pgpengine.key(pgpengine.primary).export_framed(opts)];

  pgpengine.userids.reduce((packets, userid) => {
    packets.push(userid.write(), userid.get_framed_signature_output());

    if (primary_userid === userid) {
      packets.push(signature_packet.write());
    }
  }, packets);

  opts.subkey = true;

  pgpengine.subkeys.reduce((packets, subkey) => {
    const material = pgpengine.key(subkey);
    packets.push(material.export_framed(opts), material.get_subkey_binding_signature_output());
  }, packets);

  kbpgp.util.assert_no_nulls(packets);
  return kbpgp.Buffer.concat(packets);
}

/**
 * Exports the input public key with an ascii armor and injects the signature packet.
 *
 * This is necessary because kbpgp does not support non self-signature signature
 * packets.
 *
 * @param {KeyManager} key_manager
 *    The public key_manager to export.
 * @param {Signature} signature_packet
 *    The key_manager signature to inject.
 * @returns {string}
 *    Ascii armored version of the input public key including the
 *    injected signature packet.
 */
function export_key_with_signature(key_manager, signature_packet)
{
  assert(util.isKeyManager(key_manager));
  assert(signature_packet instanceof BlindSignaturePacket);

  const user_id_packet = [key_manager.get_userids_mark_primary()[0]];

  return new Promise((resolve, reject) => {

    signature_packet.verify(
      user_id_packet,
      (err) => {
        if (err) {
          reject(new Error("Error during final signature verification. Please restart the process.", err));
        }

        const key_binary = this.export_keys_to_binary_and_inject_signature(key_manager, signature_packet);
        const key_ascii = kbpgp.armor.encode(kbpgp.const.openpgp.message_types.public_key, key_binary);
        resolve(key_ascii);
      }
    );
  });
}

const pgp_api = {
  export_keys_to_binary_and_inject_signature,
  export_key_with_signature
};

export default pgp_api