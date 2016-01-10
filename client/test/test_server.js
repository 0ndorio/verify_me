"use strict";

import { assert } from "chai"
import * as sinon from "sinon"

import RsaBlindingContext from "../src/blinding/rsa/blinding_context_rsa"
import * as server from "../src/server"
import util from "../src/util"

describe("server", function() {

  beforeEach(() => {
    this.fake_server = sinon.fakeServer.create();
    this.fake_server.autoRespond = true;
  });

  afterEach(() => {
    this.fake_server.restore();
  });

  ///---------------------------------
  /// #sendBlindingRequest()
  ///---------------------------------

  describe("#sendBlindingRequest()", () => {

    it("should return a promise", () => {
      const task = server.sendBlindingRequest().catch(() => {
      });
      assert.instanceOf(task, Promise);
    });

    it("should reject with wrong typed input for blinded_message", (done) => {

      return server.sendBlindingRequest(123)
        .catch(() => done());
    });

    it("should reject with wrong typed input for blinding_context", (done) => {

      const context = new RsaBlindingContext();
      context.hashed_token = 123;

      return server.sendBlindingRequest("1234", context)
        .catch(() => done());
    });

    it("should reject when a network error occurred", async () => {

      const context = new RsaBlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      const request_promise = server.sendBlindingRequest(util.BigInteger.ZERO, context)
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

      return server.sendBlindingRequest(util.BigInteger.ZERO, context)
        .catch(() => done());
    });

    it("should resolve and return server response if status is 200", () => {

      const expected = "deadbeef";
      this.fake_server.respondWith([200, {"Content-Type": "text/plain"}, expected]);

      let context = new RsaBlindingContext();
      context.hashed_token = util.BigInteger.ZERO;

      return server.sendBlindingRequest(util.BigInteger.ZERO, context)
        .then(answer => assert.equal(expected, answer.toRadix(16)));
    });
  });
});