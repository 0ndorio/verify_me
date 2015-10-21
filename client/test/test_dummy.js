"use strict";

var expect = require("chai").expect;
var util = require("../src/util.js");

describe("A test suite.", function() {

  beforeEach(function() {});
  afterEach(function() {});

  it("should fail", function() {
    expect(true).to.be.false;
  });

  it("should not fail", function() {
    expect(util.isString("abc")).to.be.true;
    expect(util.isString(123)).to.be.false;
  });
});
