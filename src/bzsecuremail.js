/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;
const Cm = Components.manager;

const REASON_APP_SHUTDOWN = 2;

const CATEGORY_CONTENT_LISTENER = "external-uricontentlisteners";

const TOPIC_EXAMINE = "http-on-examine-response";
const TOPIC_EXAMINE_MERGED = "http-on-examine-merged-response";

const MIMETYPE_XPKCS7 = "application/x-pkcs7-mime";
const MIMETYPE_PKCS7 = "application/pkcs7-mime";

const HANDLED_MIMETYPES = [
  MIMETYPE_XPKCS7, MIMETYPE_PKCS7
];

const FILENAME_GMAIL = "smime.p7m";

const EXPORTED_SYMBOLS = ["BugzillaSecureMail"];

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

const DEBUG = false;

function LOG(msg) {
  if (DEBUG) {
    msg = "BugzillaSecureMail: " + msg;
    Services.console.logStringMessage(msg);
    dump(msg + "\n");
  }
}

function showResultsWindow(data) {
  // For now use the view-source window. Someone else can make this prettier.
  let args = Cc["@mozilla.org/supports-array;1"]
               .createInstance(Ci.nsISupportsArray);
  let str = Cc["@mozilla.org/supports-string;1"]
              .createInstance(Ci.nsISupportsString);
  str.data = "data:text/plain," + escape(data);
  args.AppendElement(str);
  args.AppendElement(null); // charset
  args.AppendElement(null); // page descriptor
  args.AppendElement(null); // line number
  let forcedCharset = Cc["@mozilla.org/supports-PRBool;1"]
                        .createInstance(Ci.nsISupportsPRBool);
  forcedCharset.data = false;
  args.AppendElement(forcedCharset);

  Services.ww.openWindow(null, "chrome://global/content/viewSource.xul",
                         "_blank", "all,dialog=no", args);
}

function AttachmentKiller() {
}
AttachmentKiller.prototype = {
  // nsISupports
  QueryInterface: XPCOMUtils.generateQI([
    Ci.nsIObserver
  ]),

  // nsIObserver
  observe: function(subject, topic, data) {
    // This is called for *every* URI load so it needs to be as speedy as
    // possible. According to biesi there's no better way to do this presently.
    try {
      let channel = subject.QueryInterface(Ci.nsIHttpChannel);
      if (HANDLED_MIMETYPES.indexOf(channel.contentType) != -1 &&
          channel.contentDispositionFilename == FILENAME_GMAIL) {
        LOG("observe, " + channel.contentType + ", " +
            channel.contentDispositionFilename);
        channel.loadFlags &= ~Ci.nsIChannel.LOAD_CALL_CONTENT_SNIFFERS;
        channel.setResponseHeader("Content-Disposition", "", false);
      }
    }
    catch (e) { }
  }
};

function ContentListener() {
}
ContentListener.prototype = {
  _classID: Components.ID("{9a13b875-1249-40c3-a6e9-2f388306972d}"),
  _classDescription: "Bugzilla Secure Mail Content Listener",
  _contractID: "@mozilla.org/bzsecuremail/contentlistener;1",

  _loadCookie: null,
  _weakParent: null,

  _rawData: null,
  _binaryStream: null,

  // nsISupports
  QueryInterface: XPCOMUtils.generateQI([
    Ci.nsIURIContentListener, Ci.nsIStreamListener, Ci.nsIRequestObserver
  ]),

  // nsIRequestObserver
  onStartRequest: function(request, context) {
    LOG("onStartRequest");
    this._rawData = [];
    this._binaryStream = Cc["@mozilla.org/binaryinputstream;1"]
                           .createInstance(Ci.nsIBinaryInputStream);
  },

  // nsIRequestObserver
  onStopRequest: function(request, context, statusCode) {
    LOG("onStopRequest");

    let decryptedData;

    if (Components.isSuccessCode(statusCode)) {
      let rawData = this._rawData.join("");

      // nsCMSSecureMessage expects base64-encoded data.
      rawData = btoa(rawData);

      let cmsMessage = Cc["@mozilla.org/nsCMSSecureMessage;1"]
                         .createInstance(Ci.nsICMSSecureMessage);
      try {
        decryptedData = cmsMessage.receiveMessage(rawData);
      }
      catch(e) {
        LOG("receiveMessage exception: " + e);
        decryptedData = "ERROR: Unable to decrypt S/MIME message.";
      }
    }
    else {
      LOG("channel failure: " + statusCode);
      decryptedData = "ERROR: Failed to download S/MIME message.";
    }

    this._rawData = null;
    this._binaryStream = null;

    showResultsWindow(decryptedData);
  },

  // nsIStreamListener
  onDataAvailable: function(request, context, inputStream, offset, count) {
    LOG("onDataAvailable");
    this._binaryStream.setInputStream(inputStream);
    while (count > 0) {
      let bytes = this._binaryStream.readByteArray(Math.min(65535, count));
      this._rawData.push(String.fromCharCode.apply(null, bytes));
      count -= bytes.length;
      if (bytes.length == 0)
        throw "Nothing read from input stream!";
    }
  },

  // nsIURIContentListener
  onStartURIOpen: function(uri) {
    LOG("onStartURIOpen");
    return true;
  },

  // nsIURIContentListener
  doContent: function(contentType, isPreferred, request, contentHandler) {
    LOG("doContent");
    request.QueryInterface(Ci.nsIChannel).contentType = "text/plain";
    contentHandler.value = this;
    return false;
  },

  // nsIURIContentListener
  isPreferred: function(contentType, desiredContentType) {
    LOG("isPreferred");

    if (HANDLED_MIMETYPES.indexOf(contentType) != -1) {
      desiredContentType = null;
      return true;
    }

    let parent = this.parentContentListener;
    if (parent) {
      return this.parent(contentType, desiredContentType);
    }

    return false;
  },

  // nsIURIContentListener
  canHandleContent: function(contentType, isPreferred, desiredContentType) {
    LOG("canHandleContent");

    if (HANDLED_MIMETYPES.indexOf(contentType) != -1) {
      desiredContentType = null;
      return true;
    }

    let parent = this.parentContentListener;
    if (parent) {
      return this.canHandleContent(contentType, isPreferred,
                                   desiredContentType);
    }

    return false;
  },

  // nsIURIContentListener
  get loadCookie() {
    return this._loadCookie;
  },
  set loadCookie(cookie) {
    this._loadCookie = cookie;
  },

  // nsIURIContentListener
  get parentContentListener() {
    return this._weakParent ? this._weakParent.get() : null;
  },
  set parentContentListener(parent) {
    this._weakParent = parent ? Cu.getWeakReference(parent) : null;
  }
};

let BugzillaSecureMail = {
  _contentListenerFactory: null,
  _attachmentKiller: null,

  _registerAttachmentKiller: function() {
    let observer = new AttachmentKiller();
    Services.obs.addObserver(observer, TOPIC_EXAMINE, false);
    Services.obs.addObserver(observer, TOPIC_EXAMINE_MERGED, false);
    this._attachmentKiller = observer;
  },

  _unregisterAttachmentKiller: function() {
    let observer = this._attachmentKiller;
    this._attachmentKiller = null;
    Services.obs.removeObserver(observer, TOPIC_EXAMINE, false);
    Services.obs.removeObserver(observer, TOPIC_EXAMINE_MERGED, false);
  },

  _registerContentListener: function() {
    let factory = XPCOMUtils._getFactory(ContentListener);
    let proto = ContentListener.prototype;
    Cm.QueryInterface(Ci.nsIComponentRegistrar)
      .registerFactory(proto._classID, proto._classDescription,
                       proto._contractID, factory);
    this._contentListenerFactory = factory;

    let contractID = proto._contractID;
    let catMan = XPCOMUtils.categoryManager;
    for each (let mimeType in HANDLED_MIMETYPES) {
      catMan.addCategoryEntry(CATEGORY_CONTENT_LISTENER, mimeType, contractID,
                              false, true);
    }
  },

  _unregisterContentListener: function() {
    let catMan = XPCOMUtils.categoryManager;
    for each (let mimeType in HANDLED_MIMETYPES) {
      catMan.deleteCategoryEntry(CATEGORY_CONTENT_LISTENER, mimeType, false);
    }

    let factory = this._contentListenerFactory;
    this._contentListenerFactory = null;
    Cm.QueryInterface(Ci.nsIComponentRegistrar)
      .unregisterFactory(ContentListener.prototype._classID, factory);
  },

  startup: function(data, reason) {
    this._registerContentListener();
    this._registerAttachmentKiller();
  },

  shutdown: function(data, reason) {
    if (reason == REASON_APP_SHUTDOWN) {
      return;
    }
    this._unregisterAttachmentKiller();
    this._unregisterContentListener();
  }
};
