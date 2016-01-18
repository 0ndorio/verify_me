"use strict";

import fs from "fs";

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
export default function customHtmlEngine(file_path, options, callback)
{
  assert(util.isString(file_path));
  assert(util.isObject(options));
  assert(util.isFunction(callback));

  fs.readFile(file_path, (err, content) => {

    if (err || !options.hasOwnProperty("public_key")) {
      return callback(new Error(err));
    }

    const rendered = content.toString()
      .replace("{public_key}", options.public_key);

    return callback(null, rendered);
  });
}