"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = customHtmlEngine;

var _fs = require("fs");

var _fs2 = _interopRequireDefault(_fs);

var _verifyme_utility = require("verifyme_utility");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Template engine that replaces the a key place holder with a given ascii key string.
 *
 * @param {string} file_path
 *    Path to the requested html file.
 *
 * @param {object} options
 *    Object containing the ascii key string.
 *
 * @param {function.<Error, string>} callback
 *    A callback given from express which receives
 *    the an Error or the manipulated html string.
 *
 * @return {*}
 *    Result of the given callback.
 */
function customHtmlEngine(file_path, options, callback) {
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isString(file_path));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isObject(options));
  (0, _verifyme_utility.assert)(_verifyme_utility.check.isFunction(callback));

  _fs2.default.readFile(file_path, function (err, content) {

    if (err || !options.hasOwnProperty("public_key")) {
      return callback(new Error(err));
    }

    var rendered = content.toString().replace("{public_key}", options.public_key);

    return callback(null, rendered);
  });
}