/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const Cu = Components.utils;

let componentURL = null;

function startup(data, reason) {
  componentURL = data.resourceURI.spec + "bzsecuremail.js";
  Cu.import(componentURL);
  BugzillaSecureMail.startup(data, reason);
}

function shutdown(data, reason) {
  BugzillaSecureMail.shutdown(data, reason);
  Cu.unload(componentURL);
  componentURL = null;
}

function install(data, reason) {
}

function uninstall(data, reason) {
}
