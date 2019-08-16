"use strict";

import { assert } from "chai"
import * as sinon from "sinon"
import { BigInteger, check } from "verifyme_utility"

import RsaBlindingContext from "../src/blinding/rsa/blinding_context_rsa"
import server from "../src/server_requests"
import { fail } from "assert";

describe("server", function() {

  var fake_server;

  beforeEach(() => {
    fake_server = sinon.fakeServer.create();
    fake_server.autoRespond = true;
    fake_server.respondImmediately = true;
  })

  afterEach(() => {
    fake_server.restore();
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
      server.requestRsaBlinding(123)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should reject with wrong typed input for blinding_context", (done) => {

      const context = new RsaBlindingContext();
      context.hashed_token = 123;

      server.requestRsaBlinding("1234", context)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should reject when a network error occurred", (done) => {

      fake_server.autoRespond = false;
      fake_server.respondImmediately = false;

      const context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      const request_promise = server.requestRsaBlinding(BigInteger.ZERO, context)
        .then(() => fail("should never succeed"))
        .catch(() => done());

      assert.equal(1, fake_server.requestCount);
      fake_server.requests[0].abort();
    });

    it("should reject and return status text error if status is not 200", (done) => {

      const expected = {code: 404, status_text: new Error("Not Found")};
      fake_server.respondWith([expected.code, {"Content-Type": "text/plain"}, ""]);

      let context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      server.requestRsaBlinding(BigInteger.ZERO, context)
        .then(() => fail("should never succeed"))
        .catch(() => done());
    });

    it("should resolve and return server response if status is 200", async () =>{

      const expected = "deadbeef";
      const answer = JSON.stringify({signed_blinded_message: expected});
      fake_server.respondWith("/rsa", [200, {"Content-Type": "text/plain", "Content-Length": answer.length}, answer]);

      let context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      const result = await server.requestRsaBlinding(BigInteger.ZERO, context);
      assert.equal(expected, result.toRadix(32));
    });
  });
});