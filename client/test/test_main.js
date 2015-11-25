"use strict";

var BlindingInformation= require("../src/types/blinding_information");
var controls = require("./helper/helper").controls;
var main = require("../src/main");
var util = require("../src/util");

var assert = require("chai").assert;
var sinon = require('sinon');

describe("main", function() {

  //
  // suite functions
  //
  var xhr = null;
  var requests = null;

  before(function() {
    xhr = sinon.useFakeXMLHttpRequest();
    xhr.onCreate = function (req) { requests.push(req); };
  });

  beforeEach(function() {
    requests = [];
    controls.loadFixture("test/fixture/keys_1024bit.html");
  });

  afterEach(function() {});

  after(function() {
    xhr.restore();
  });


  //
  // test cases
  //

  describe("#serverRequest()", function() {

    it("should return a promise", function() {
      assert.instanceOf(main.serverRequest(), Promise);
    });

    it("should reject with wrong typed input for blinded_message", function() {

      return main.serverRequest(123)
        .then(function() { assert.fail(); })
        .catch(function(error) {
          assert.typeOf(error, 'string');
        });
    });

    it("should reject with wrong typed input for blinding_information", function(done) {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = 123;

      return main.serverRequest("1234", blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.typeOf(error, 'string');
          done();
        });
    });

    it("should reject when a network error occures", function(done) {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      var request_promise = main.serverRequest("1234", blinding_information)
        .then(function (answer) { done("Should not happend: " + answer); })
        .catch(function(error) {
          assert.instanceOf(error, Error);
          done();
        });

      assert.equal(1, requests.length);
      requests[0].onload = null;
      requests[0].abort();

      return request_promise;
    });

    it("should reject and return status text error if status is not 200", function(done) {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      var expected = { code: 404, status_text: new Error("Not Found") };

      var request_promise = main.serverRequest("" , blinding_information)
        .then(function(answer) { done(answer); })
        .catch(function(error) {
          assert.instanceOf(error, Error);
          done();
        });

      assert.equal(1, requests.length);
      requests[0].respond(expected.code, { "Content-Type": "text/plain" }, "");

      return request_promise;
    });

    it("should resolve and return server response if status is 200", function() {

      var blinding_information = new BlindingInformation();
      blinding_information.hashed_token = util.bytes2MPI("\u0000").data;

      var expected = "My expected response";

      var request_promise = main.serverRequest("" , blinding_information)
        .then(function(answer) {
          assert.equal(expected, answer);
        });

      assert.equal(1, requests.length);
      requests[0].respond(200, { "Content-Type": "text/plain" }, expected);

      return request_promise;
    });
  });

  describe("#requestPseudonym()", function() {

    it("should output a valid pgp key with a server generated signature");
    it("should throw if token input is invalid");
    it("should throw if server public key input is invalid");
    it("should throw if client public key input is invalid");
  });
});