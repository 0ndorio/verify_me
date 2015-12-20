"use strict";

var kbpgp = require("kbpgp");

module.exports = {

  /// TODO
  export_keys_to_binary_and_inject_signature: function (keymanager,  signature, opts)
  {
    var pgpengine = keymanager.pgp;
    var primary_userid = keymanager.get_userids_mark_primary()[0];

    var packets = [pgpengine.key(pgpengine.primary).export_framed(opts)];
    pgpengine.userids.forEach(function(userid) {
      packets.push(userid.write(), userid.get_framed_signature_output());

      if (primary_userid === userid) {
        packets.push(signature.write());
      }
    });

    opts.subkey = true;

    pgpengine.subkeys.forEach(function(subkey) {
      var material = pgpengine.key(subkey);
      packets.push(material.export_framed(opts), material.get_subkey_binding_signature_output());
    });

    kbpgp.util.assert_no_nulls(packets);
    return kbpgp.Buffer.concat(packets);
  },

  export_key_with_signature: function(key, signature_packet)
  {
    var key_binary = this.export_keys_to_binary_and_inject_signature(key, signature_packet, {});
    var key_ascii = kbpgp.armor.encode(kbpgp.const.openpgp.message_types.public_key, key_binary);

    var target_key_material = [key.get_userids_mark_primary()[0]];

    return new Promise(function(resolve, reject) {
      signature_packet.verify(target_key_material,
        function(err) {
          if (err) {
            reject(new Error("Error during final signature verification. Please restart the process.", err));
          } else {
            resolve(key_ascii);
          }
        }
      );
    });
  }
};