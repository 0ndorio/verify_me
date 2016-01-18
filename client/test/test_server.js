"use strict";

import { assert } from "chai"
import * as sinon from "sinon"

import RsaBlindingContext from "../src/blinding/rsa/blinding_context_rsa"
import server from "../src/server_requests"
import util from "verifyme_utility"

describe("server", function() {

  beforeEach(() => {
    this.fake_server = sinon.fakeServer.create();
    this.fake_server.autoRespond = true;
  });

  afterEach(() => {
    this.fake_server.restore();
  });

  ///---------------------------------
  /// #requestRsaBlinding()
  ///---------------------------------

  describe("#requestRsaBlinding()", () => {

    it("should return a promise", () => {
      const task = server.requestRsaBlinding().catch(() => {});
      assert.instanceOf(task, Promise);
    });

    it("should reject with wrong typed input for blinded_message", (done) => {

      return server.requestRsaBlinding(123)
        .catch(() => done());
    });

    it("should reject with wrong typed input for blinding_context", (done) => {

      const context = new RsaBlindingContext();
      context.hashed_token = 123;

      return server.requestRsaBlinding("1234", context)
        .catch(() => done());
    });

    it("should reject when a network error occurred", async () => {

      const context = new RsaBlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      const request_promise = server.requestRsaBlinding(util.BigInteger.ZERO, context)
        .catch(error => assert.instanceOf(error, Error));

      assert.equal(1, this.fake_server.requests.length);
      this.fake_server.requests[0].onload = null;
      this.fake_server.requests[0].abort();

      return request_promise;
    });

    it("should reject and return status text error if status is not 200", (done) => {

      const expected = {code: 404, status_text: new Error("Not Found")};
      this.fake_server.respondWith([expected.code, {"Content-Type": "text/plain"}, ""]);

      let context = new RsaBlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      return server.requestRsaBlinding(util.BigInteger.ZERO, context)
        .catch(() => done());
    });

    it("should resolve and return server response if status is 200", () =>{

      const expected = "deadbeef";
      const answer = JSON.stringify({signed_blinded_message: expected});
      this.fake_server.respondWith([200, {"Content-Type": "text/plain"}, answer]);

      let context = new RsaBlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      return server.requestRsaBlinding(util.BigInteger.ZERO, context)
        .then(answer => assert.equal(expected, answer.toRadix(32)));
    });
  });
});