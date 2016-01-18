"use strict";

import { assert } from "chai"

import BlindSignaturePacket from "../../src/pgp/blind_signature_packet"
import pgp from "../../src/pgp/pgp"
import { check } from "verifyme_utility"

import sample_keys from "../helper/keys"

describe("pgp", function() {

  before(async () => {
    this.key_manager = await check.generateKeyFromString(sample_keys.rsa[1024].pub);
  });

  beforeEach(async () => {
    const key_manager = this.key_manager;

    this.signature_packet = key_manager.primary._pgp.get_psc().all[0].sig;
  });

  afterEach(() => {});

  ///-----------------------------------------------
  /// #exportKeyToBinaryAndInjectSignature()
  ///-----------------------------------------------

  describe("#exportKeyToBinaryAndInjectSignature()", () => {

    it("should throw if input has no {KeyManager}", () => {
      assert.throws(() => pgp.exportKeyToBinaryAndInjectSignature(null, this.signature_packet));
    });

    it("should throw if input has no {BlindSignaturePacket}", () => {
      assert.throws(() => pgp.exportKeyToBinaryAndInjectSignature(this.key_manager, null));
    });

    it("should throw if opts are no {object}", () => {
      assert.throws(() => pgp.exportKeyToBinaryAndInjectSignature(this.key_manager, this.signature_packet, 123));
    });

    it("should return a {Buffer} containg the signature if input is valid", () => {
      const result = pgp.exportKeyToBinaryAndInjectSignature(this.key_manager, this.signature_packet);
      assert.isTrue(check.isBuffer(result));

      const userid = this.key_manager.get_userids_mark_primary()[0];
      const userid_buffer = userid.get_framed_signature_output();
      const userid_buffer_index = result.indexOf(userid_buffer);
      assert.isBelow(-1, userid_buffer_index);

      const signature_buffer = this.signature_packet.replay();
      const signature_buffer_index = result.indexOf(signature_buffer);
      assert.isBelow(-1, signature_buffer_index);

      const start = userid_buffer_index +  userid_buffer.length;
      const end = start + signature_buffer.length;
      const slice = result.slice(start, end);
      assert.isTrue(signature_buffer.equals(slice));
    });
  });

  ///-----------------------------------------------
  /// #exportKeyToAsciiWithSignature()
  ///-----------------------------------------------

  describe("#exportKeyToAsciiWithSignature()", () => {

    it("should throw if input has no {KeyManager}", () => {
      assert.throws(() => pgp.exportKeyToAsciiWithSignature(null, this.signature_packet));
    });

    it("should throw if input has no {BlindSignaturePacket}", () => {
      assert.throws(() => pgp.exportKeyToAsciiWithSignature(this.key_manager, null));
    });

    it("should return the promise of an ascii armored key {string} if input is valid", () => {
      const result = pgp.exportKeyToAsciiWithSignature(this.key_manager, this.signature_packet);
      assert.instanceOf(result, Promise);

      return result
        .then(key_ascii => check.generateKeyFromString(key_ascii))
        .then(key_manager => assert.isTrue(check.isKeyManager(key_manager)));
    });
  });
});