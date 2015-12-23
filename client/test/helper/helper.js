"use strict";

import { assert } from "chai"
import * as client from "../../src/client"

/// Utility API for html interaction.
module.exports = {
  controls: {
    get serverPublicKey() {
      return document.getElementById(client.server_public_key_element_id).innerHTML;
    },
    set serverPublicKey(val) {
      document.getElementById(client.server_public_key_element_id).innerHTML = val;
    },

    get userPublicKeyString() {
      return document.getElementById(client.user_public_key_element_id).value;
    },
    set userPublicKeyString(val) {
      document.getElementById(client.user_public_key_element_id).value = val;
    },

    get userTokenString() {
      return document.getElementById(client.user_token_element_id).value;
    },
    set userTokenString(val) {
      document.getElementById(client.user_token_element_id).value = val;
    },

    loadFixture: function(fixture) {
      if (!window.__html__) {
        assert.fail("Missing: " + fixture);
      }

      document.body.innerHTML = window.__html__[fixture];
      return true;
    }
  }
};