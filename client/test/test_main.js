"use strict";

var assert = require("chai").assert;
var controls = require("./helper/helper").controls;
var main = require("../src/main");

describe("main", function() {

  //
  // suite functions
  //

  beforeEach(function() {
    controls.loadFixture("test/fixture/keys_2048bit.html");
  });

  afterEach(function() {
  });

  //
  // test cases
  //

  describe("#requestPseudonym()", function() {

    it("should output a valid pgp key with a server generated signature");
    it("should throw if token input is invalid");
    it("should throw if server public key input is invalid");
    it("should throw if client public key input is invalid");
  });
});