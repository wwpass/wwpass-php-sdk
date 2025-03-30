(function () {
  'use strict';

  function _classCallCheck(instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  }

  function _defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      Object.defineProperty(target, descriptor.key, descriptor);
    }
  }

  function _createClass(Constructor, protoProps, staticProps) {
    if (protoProps) _defineProperties(Constructor.prototype, protoProps);
    if (staticProps) _defineProperties(Constructor, staticProps);
    return Constructor;
  }

  function _defineProperty(obj, key, value) {
    if (key in obj) {
      Object.defineProperty(obj, key, {
        value: value,
        enumerable: true,
        configurable: true,
        writable: true
      });
    } else {
      obj[key] = value;
    }

    return obj;
  }

  function ownKeys(object, enumerableOnly) {
    var keys = Object.keys(object);

    if (Object.getOwnPropertySymbols) {
      var symbols = Object.getOwnPropertySymbols(object);
      if (enumerableOnly) symbols = symbols.filter(function (sym) {
        return Object.getOwnPropertyDescriptor(object, sym).enumerable;
      });
      keys.push.apply(keys, symbols);
    }

    return keys;
  }

  function _objectSpread2(target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i] != null ? arguments[i] : {};

      if (i % 2) {
        ownKeys(Object(source), true).forEach(function (key) {
          _defineProperty(target, key, source[key]);
        });
      } else if (Object.getOwnPropertyDescriptors) {
        Object.defineProperties(target, Object.getOwnPropertyDescriptors(source));
      } else {
        ownKeys(Object(source)).forEach(function (key) {
          Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
        });
      }
    }

    return target;
  }

  function _inherits(subClass, superClass) {
    if (typeof superClass !== "function" && superClass !== null) {
      throw new TypeError("Super expression must either be null or a function");
    }

    subClass.prototype = Object.create(superClass && superClass.prototype, {
      constructor: {
        value: subClass,
        writable: true,
        configurable: true
      }
    });
    if (superClass) _setPrototypeOf(subClass, superClass);
  }

  function _getPrototypeOf(o) {
    _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) {
      return o.__proto__ || Object.getPrototypeOf(o);
    };
    return _getPrototypeOf(o);
  }

  function _setPrototypeOf(o, p) {
    _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) {
      o.__proto__ = p;
      return o;
    };

    return _setPrototypeOf(o, p);
  }

  function isNativeReflectConstruct() {
    if (typeof Reflect === "undefined" || !Reflect.construct) return false;
    if (Reflect.construct.sham) return false;
    if (typeof Proxy === "function") return true;

    try {
      Date.prototype.toString.call(Reflect.construct(Date, [], function () {}));
      return true;
    } catch (e) {
      return false;
    }
  }

  function _construct(Parent, args, Class) {
    if (isNativeReflectConstruct()) {
      _construct = Reflect.construct;
    } else {
      _construct = function _construct(Parent, args, Class) {
        var a = [null];
        a.push.apply(a, args);
        var Constructor = Function.bind.apply(Parent, a);
        var instance = new Constructor();
        if (Class) _setPrototypeOf(instance, Class.prototype);
        return instance;
      };
    }

    return _construct.apply(null, arguments);
  }

  function _isNativeFunction(fn) {
    return Function.toString.call(fn).indexOf("[native code]") !== -1;
  }

  function _wrapNativeSuper(Class) {
    var _cache = typeof Map === "function" ? new Map() : undefined;

    _wrapNativeSuper = function _wrapNativeSuper(Class) {
      if (Class === null || !_isNativeFunction(Class)) return Class;

      if (typeof Class !== "function") {
        throw new TypeError("Super expression must either be null or a function");
      }

      if (typeof _cache !== "undefined") {
        if (_cache.has(Class)) return _cache.get(Class);

        _cache.set(Class, Wrapper);
      }

      function Wrapper() {
        return _construct(Class, arguments, _getPrototypeOf(this).constructor);
      }

      Wrapper.prototype = Object.create(Class.prototype, {
        constructor: {
          value: Wrapper,
          enumerable: false,
          writable: true,
          configurable: true
        }
      });
      return _setPrototypeOf(Wrapper, Class);
    };

    return _wrapNativeSuper(Class);
  }

  function _assertThisInitialized(self) {
    if (self === void 0) {
      throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
    }

    return self;
  }

  function _possibleConstructorReturn(self, call) {
    if (call && (typeof call === "object" || typeof call === "function")) {
      return call;
    }

    return _assertThisInitialized(self);
  }

  function _slicedToArray(arr, i) {
    return _arrayWithHoles(arr) || _iterableToArrayLimit(arr, i) || _nonIterableRest();
  }

  function _arrayWithHoles(arr) {
    if (Array.isArray(arr)) return arr;
  }

  function _iterableToArrayLimit(arr, i) {
    if (!(Symbol.iterator in Object(arr) || Object.prototype.toString.call(arr) === "[object Arguments]")) {
      return;
    }

    var _arr = [];
    var _n = true;
    var _d = false;
    var _e = undefined;

    try {
      for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
        _arr.push(_s.value);

        if (i && _arr.length === i) break;
      }
    } catch (err) {
      _d = true;
      _e = err;
    } finally {
      try {
        if (!_n && _i["return"] != null) _i["return"]();
      } finally {
        if (_d) throw _e;
      }
    }

    return _arr;
  }

  function _nonIterableRest() {
    throw new TypeError("Invalid attempt to destructure non-iterable instance");
  }

  /* Constants */

  /* Status codes */
  var WWPASS_OK_MSG = 'OK';
  var WWPASS_STATUS = {
    CONTINUE: 100,
    OK: 200,
    INTERNAL_ERROR: 400,
    ALREADY_PERSONALIZED: 401,
    PASSWORD_MISMATCH: 402,
    PASSWORD_LOCKOUT: 403,
    WRONG_KEY: 404,
    WRONG_KEY_SECOND: 405,
    NOT_A_KEY: 406,
    NOT_A_KEY_SECOND: 407,
    KEY_DISABLED: 408,
    NOT_ALLOWED: 409,
    BLANK_TOKEN: 410,
    BLANK_SECOND_TOKEN: 411,
    ACTIVITY_PROFILE_LOCKED: 412,
    SSL_REQUIRED: 413,
    BLANK_NORMAL_TOKEN: 414,
    BLANK_SECOND_NORMAL_TOKEN: 415,
    BLANK_MASTER_TOKEN: 416,
    BLANK_SECOND_MASTER_TOKEN: 417,
    NOT_ACTIVATED_TOKEN: 418,
    NOT_ACTIVATED_SECOND_TOKEN: 419,
    WRONG_KEY_SET: 420,
    NO_VERIFIER: 421,
    INCOMPLETE_KEYSET: 422,
    INVALID_TICKET: 423,
    SAME_TOKEN: 424,
    NO_RECOVERY_INFO: 425,
    BAD_RECOVERY_REQUEST: 426,
    RECOVERY_FAILED: 427,
    TERMINAL_ERROR: 500,
    TERMINAL_NOT_FOUND: 501,
    TERMINAL_BAD_REQUEST: 502,
    NO_CONNECTION: 503,
    NETWORK_ERROR: 504,
    PROTOCOL_ERROR: 505,
    UNKNOWN_HANDLER: 506,
    TERMINAL_CANCELED: 590,
    TIMEOUT: 600,
    TICKET_TIMEOUT: 601,
    USER_REJECT: 603,
    NO_AUTH_INTERFACES_FOUND: 604,
    TERMINAL_TIMEOUT: 605,
    UNSUPPORTED_PLATFORM: 606
  };
  var WWPASS_NO_AUTH_INTERFACES_FOUND_MSG = 'No WWPass SecurityPack is found on your computer or WWPass Browser Plugin is disabled';
  var WWPASS_UNSUPPORTED_PLATFORM_MSG_TMPL = 'WWPass authentication is not supported on';
  var WWPASS_KEY_TYPE_PASSKEY = 'passkey';
  var WWPASS_KEY_TYPE_DEFAULT = WWPASS_KEY_TYPE_PASSKEY;

  var connectionPool = [];

  var closeConnectionPool = function closeConnectionPool() {
    while (connectionPool.length) {
      var connection = connectionPool.shift();

      if (connection.readyState === WebSocket.OPEN) {
        connection.close();
      }
    }
  };

  var applyDefaults = function applyDefaults(initialOptions) {
    var defaultOptions = {
      ppx: 'wwp_',
      version: 2,
      ticket: undefined,
      callbackURL: undefined,
      returnErrors: false,
      log: function log() {},
      development: false,
      spfewsAddress: 'wss://spfews.wwpass.com',
      echo: undefined
    };
    return _objectSpread2({}, defaultOptions, {}, initialOptions);
  };
  /**
  * WWPass SPFE WebSocket connection
  * @param {object} options
  *
  * options = {
  *   'ticket': undefined, // stirng
  *   'callbackURL': undefined, //string
  *   'development': false || 'string' , // work with another spfews.wwpass.* server
  *   'log': function (message) || console.log, // another log handler
  *   'echo': undefined
  * }
  */


  var getWebSocketResult = function getWebSocketResult(initialOptions) {
    return new Promise(function (resolve, reject) {
      var options = applyDefaults(initialOptions);
      var clientKey = null;
      var originalTicket = options.ticket;
      var ttl = null;

      var settle = function settle(status, reason) {
        if (status === 200) {
          resolve({
            ppx: options.ppx,
            version: options.version,
            status: status,
            reason: WWPASS_OK_MSG,
            ticket: options.ticket,
            callbackURL: options.callbackURL,
            clientKey: clientKey,
            originalTicket: originalTicket,
            ttl: ttl
          });
        } else {
          reject({
            ppx: options.ppx,
            version: options.version,
            status: status,
            reason: reason,
            ticket: options.ticket,
            callbackURL: options.callbackURL
          });
        }
      };

      if (!('WebSocket' in window)) {
        settle(WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket is not supported.');
        return;
      }

      var websocketurl = options.spfewsAddress;
      var socket = new WebSocket(websocketurl);
      connectionPool.push(socket);
      var log = options.log;

      socket.onopen = function () {
        try {
          log("Connected: ".concat(websocketurl));
          var message = JSON.stringify({
            ticket: options.ticket
          });
          log("Sent message to server: ".concat(message));
          socket.send(message);
        } catch (error) {
          log(error);
          settle(WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error');
        }
      };

      socket.onclose = function () {
        try {
          var index = connectionPool.indexOf(socket);

          if (index !== -1) {
            connectionPool.splice(index, 1);
          }

          log('Disconnected');
          resolve({
            refresh: true
          });
        } catch (error) {
          log(error);
          settle(WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error');
        }
      };

      socket.onmessage = function (message) {
        try {
          log("Message received from server: ".concat(message.data));
          var response = JSON.parse(message.data);
          var status = response.code;
          var reason = response.reason;

          if ('clientKey' in response && !clientKey) {
            clientKey = response.clientKey;

            if (response.originalTicket !== undefined) {
              originalTicket = response.originalTicket;
              ttl = response.ttl;
            }
          }

          if (status === 100) {
            return;
          }

          settle(status, reason);
          socket.close();
        } catch (error) {
          log(error);
          settle(WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error');
        }
      };
    });
  };

  var abToB64 = function abToB64(data) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
  };

  var b64ToAb = function b64ToAb(base64) {
    var s = atob(base64);
    var bytes = new Uint8Array(s.length);

    for (var i = 0; i < s.length; i += 1) {
      bytes[i] = s.charCodeAt(i);
    }

    return bytes.buffer;
  };

  var ab2str = function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
  };

  var str2ab = function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char

    var bufView = new Uint16Array(buf);

    for (var i = 0, strLen = str.length; i < strLen; i += 1) {
      bufView[i] = str.charCodeAt(i);
    }

    return buf;
  };

  var crypto = window.crypto || window.msCrypto;
  var subtle = crypto ? crypto.webkitSubtle || crypto.subtle : null;

  var encodeClientKey = function encodeClientKey(key) {
    return abToB64(key).replace(/\+/g, '-').replace(/[/]/g, '.').replace(/=/g, '_');
  };

  var encrypt = function encrypt(options, key, data) {
    return subtle.encrypt(options, key, data);
  };

  var decrypt = function decrypt(options, key, data) {
    return subtle.decrypt(options, key, data);
  };

  var importKey = function importKey(format, key, algoritm, extractable, operations) {
    return subtle.importKey(format, key, algoritm, extractable, operations);
  }; // eslint-disable-line max-len


  var getRandomData = function getRandomData(buffer) {
    return crypto.getRandomValues(buffer);
  };

  var concatBuffers = function concatBuffers() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    var totalLen = args.reduce(function (accumulator, curentAB) {
      return accumulator + curentAB.byteLength;
    }, 0);
    var i = 0;
    var result = new Uint8Array(totalLen);

    while (args.length > 0) {
      result.set(new Uint8Array(args[0]), i);
      i += args[0].byteLength;
      args.shift();
    }

    return result.buffer;
  };

  var isClientKeyTicket = function isClientKeyTicket(ticket) {
    var _ticket$split = ticket.split('@'),
        _ticket$split2 = _slicedToArray(_ticket$split, 1),
        info = _ticket$split2[0];

    var spnameFlagsOTP = info.split(':');

    if (spnameFlagsOTP.length < 3) {
      return false;
    }

    var FLAGS_INDEX = 1; // second element of ticket — flags

    var flags = spnameFlagsOTP[FLAGS_INDEX];
    return flags.split('').some(function (element) {
      return element === 'c';
    });
  };

  var ticketAdapter = function ticketAdapter(response) {
    if (response && response.data) {
      var ticket = {
        ticket: response.data,
        ttl: response.ttl || 120
      };
      delete ticket.data;
      return ticket;
    }

    return response;
  };

  var WWPassError =
  /*#__PURE__*/
  function (_Error) {
    _inherits(WWPassError, _Error);

    function WWPassError(code) {
      var _this;

      _classCallCheck(this, WWPassError);

      for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
        args[_key - 1] = arguments[_key];
      }

      _this = _possibleConstructorReturn(this, _getPrototypeOf(WWPassError).call(this, args, WWPassError));
      Error.captureStackTrace(_assertThisInitialized(_this), WWPassError);
      _this.code = code;
      return _this;
    }

    _createClass(WWPassError, [{
      key: "toString",
      value: function toString() {
        return "".concat(this.name, "(").concat(this.code, "): ").concat(this.message);
      }
    }]);

    return WWPassError;
  }(_wrapNativeSuper(Error));

  var exportKey = function exportKey(type, key) {
    return subtle.exportKey(type, key);
  }; // generate digest from string


  var hex = function hex(buffer) {
    var hexCodes = [];
    var view = new DataView(buffer);

    for (var i = 0; i < view.byteLength; i += 4) {
      // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
      var value = view.getUint32(i); // toString(16) will give the hex representation of the number without padding

      var stringValue = value.toString(16); // We use concatenation and slice for padding

      var padding = '00000000';
      var paddedValue = (padding + stringValue).slice(-padding.length);
      hexCodes.push(paddedValue);
    } // Join all the hex strings into one


    return hexCodes.join('');
  }; // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest


  var sha256 = function sha256(str) {
    // We transform the string into an arraybuffer.
    var buffer = str2ab(str);
    return subtle.digest({
      name: 'SHA-256'
    }, buffer).then(function (hash) {
      return hex(hash);
    });
  };

  var clean = function clean(items) {
    var currentDate = window.Date.now();
    return items.filter(function (item) {
      return item.deadline > currentDate;
    });
  };

  var loadNonces = function loadNonces() {
    var wwpassNonce = window.localStorage.getItem('wwpassNonce');

    if (!wwpassNonce) {
      return [];
    }

    try {
      return clean(JSON.parse(wwpassNonce));
    } catch (error) {
      window.localStorage.removeItem('wwpassNonce');
      throw error;
    }
  };

  var saveNonces = function saveNonces(nonces) {
    window.localStorage.setItem('wwpassNonce', JSON.stringify(nonces));
  }; // get from localStorage Client Nonce


  var getClientNonce = function getClientNonce(ticket) {
    var newTTL = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;

    if (!subtle) {
      throw new WWPassError(WWPASS_STATUS.SSL_REQUIRED, 'Client-side encryption requires https.');
    }

    var nonces = loadNonces();
    return sha256(ticket).then(function (hash) {
      var nonce = nonces.find(function (it) {
        return hash === it.hash;
      });
      var key = nonce && nonce.key ? b64ToAb(nonce.key) : undefined;

      if (newTTL && key) {
        nonce.deadline = window.Date.now() + newTTL * 1000;
        saveNonces(nonces);
      }

      return key;
    });
  }; // generate Client Nonce and set it to localStorage


  var generateClientNonce = function generateClientNonce(ticket) {
    var ttl = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 120;

    if (!subtle) {
      throw new WWPassError(WWPASS_STATUS.SSL_REQUIRED, 'Client-side encryption requires https.');
    }

    return getClientNonce(ticket).then(function (loadedKey) {
      if (loadedKey) {
        return loadedKey;
      }

      return subtle.generateKey({
        name: 'AES-CBC',
        length: 256
      }, true, // is extractable
      ['encrypt', 'decrypt']).then(function (key) {
        return exportKey('raw', key);
      }).then(function (rawKey) {
        return sha256(ticket).then(function (digest) {
          var nonce = {
            hash: digest,
            key: abToB64(rawKey),
            deadline: window.Date.now() + ttl * 1000
          };
          var nonces = loadNonces();
          nonces.push(nonce);
          saveNonces(nonces); // hack for return key

          return rawKey;
        });
      });
    });
  };

  var getClientNonceWrapper = function getClientNonceWrapper(ticket) {
    var ttl = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 120;

    if (!isClientKeyTicket(ticket)) {
      return new Promise(function (resolve) {
        resolve(undefined);
      });
    }

    return generateClientNonce(ticket, ttl);
  };

  var copyClientNonce = function copyClientNonce(oldTicket, newTicket, ttl) {
    return getClientNonce(oldTicket).then(function (nonceKey) {
      return sha256(newTicket) // eslint-disable-line max-len
      .then(function (digest) {
        var nonces = loadNonces();
        nonces.push({
          hash: digest,
          key: abToB64(nonceKey),
          deadline: window.Date.now() + ttl * 1000
        });
        saveNonces(nonces);
      });
    });
  };

  var clientKeyIV = new Uint8Array([176, 178, 97, 142, 156, 31, 45, 30, 81, 210, 85, 14, 202, 203, 86, 240]);

  var WWPassCryptoPromise =
  /*#__PURE__*/
  function () {
    _createClass(WWPassCryptoPromise, [{
      key: "encryptArrayBuffer",
      value: function encryptArrayBuffer(arrayBuffer) {
        var iv = new Uint8Array(this.ivLen);
        getRandomData(iv);
        var algorithm = this.algorithm;
        Object.assign(algorithm, {
          iv: iv
        });
        return encrypt(algorithm, this.clientKey, arrayBuffer).then(function (encryptedAB) {
          return concatBuffers(iv.buffer, encryptedAB);
        });
      }
    }, {
      key: "encryptString",
      value: function encryptString(string) {
        return this.encryptArrayBuffer(str2ab(string)).then(abToB64);
      }
    }, {
      key: "decryptArrayBuffer",
      value: function decryptArrayBuffer(encryptedArrayBuffer) {
        var algorithm = this.algorithm;
        Object.assign(algorithm, {
          iv: encryptedArrayBuffer.slice(0, this.ivLen)
        });
        return decrypt(algorithm, this.clientKey, encryptedArrayBuffer.slice(this.ivLen));
      }
    }, {
      key: "decryptString",
      value: function decryptString(encryptedString) {
        return this.decryptArrayBuffer(b64ToAb(encryptedString)).then(ab2str);
      } // Private

    }], [{
      key: "getWWPassCrypto",

      /* Return Promise that will be resloved to catual crypto object
      with encrypt/decrypt String/ArrayBuffer methods and cleintKey member.
      Ticket must be authenticated with 'c' auth factor.
      Only supported values for algorithm are 'AES-GCM' and 'AES-CBC'.
      */
      value: function getWWPassCrypto(ticket) {
        var algorithmName = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'AES-GCM';
        var encryptedClientKey = null;
        var algorithm = {
          name: algorithmName,
          length: 256
        };
        return getWebSocketResult({
          ticket: ticket,
          clientKeyOnly: true
        }).then(function (result) {
          if (!result.clientKey) {
            throw Error("No client key associated with the ticket ".concat(ticket));
          }

          encryptedClientKey = result.clientKey;
          return getClientNonce(result.originalTicket ? result.originalTicket : ticket, result.ttl);
        }).then(function (key) {
          if (!key) {
            throw new Error('No client key nonce associated with the ticket in this browser');
          }

          return importKey('raw', key, {
            name: 'AES-CBC'
          }, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
        }).then(function (clientKeyNonce) {
          return decrypt({
            name: 'AES-CBC',
            iv: clientKeyIV
          }, clientKeyNonce, b64ToAb(encryptedClientKey));
        }).then(function (arrayBuffer) {
          return importKey('raw', arrayBuffer, algorithm, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
        }).then(function (key) {
          return new WWPassCryptoPromise(key, algorithm);
        })["catch"](function (error) {
          if (error.reason !== undefined) {
            throw new Error(error.reason);
          }

          throw error;
        });
      }
    }]);

    function WWPassCryptoPromise(key, algorithm) {
      _classCallCheck(this, WWPassCryptoPromise);

      this.ivLen = algorithm.name === 'AES-GCM' ? 12 : 16;
      this.algorithm = algorithm;

      if (algorithm.name === 'AES-GCM') {
        Object.assign(this.algorithm, {
          tagLength: 128
        });
      }

      this.clientKey = key;
    }

    return WWPassCryptoPromise;
  }();

  var noCacheHeaders = {
    pragma: 'no-cache',
    'cache-control': 'no-cache'
  };

  var getTicket = function getTicket(url) {
    return fetch(url, {
      cache: 'no-store',
      headers: noCacheHeaders
    }).then(function (response) {
      if (!response.ok) {
        throw Error("Error fetching ticket from \"".concat(url, "\": ").concat(response.statusText));
      }

      return response.json();
    });
  };
  /* updateTicket should be called when the client wants to extend the session beyond
    ticket's TTL. The URL handler on the server should use putTicket to get new ticket
    whith the same credentials as the old one. The URL should return JSON object:
    {"oldTicket": "<previous_ticket>", "newTicket": "<new_ticket>", "ttl": <new_ticket_ttl>}
    The functions ultimately resolves to:
    {"ticket": "<new_ticket>", "ttl": <new_ticket_ttl>}
  */


  var updateTicket = function updateTicket(url) {
    return fetch(url, {
      cache: 'no-store',
      headers: noCacheHeaders
    }).then(function (response) {
      if (!response.ok) {
        throw Error("Error updating ticket from \"".concat(url, "\": ").concat(response.statusText));
      }

      return response.json();
    }).then(function (response) {
      if (!response.newTicket || !response.oldTicket || !response.ttl) {
        throw Error("Invalid response ot updateTicket: ".concat(response));
      }

      var result = {
        ticket: response.newTicket,
        ttl: response.ttl
      };

      if (!isClientKeyTicket(response.newTicket)) {
        return result;
      } // We have to call getWebSocketResult and getClientNonce to check for Nonce and update
      // TTL on original ticket


      return getWebSocketResult({
        ticket: response.newTicket,
        clientKeyOnly: true
      }).then(function (wsResult) {
        if (!wsResult.clientKey) {
          throw Error("No client key associated with the ticket ".concat(response.newTicket));
        }

        return getClientNonce(wsResult.originalTicket ? wsResult.originalTicket : response.newTicket, wsResult.ttl);
      }).then(function () {
        return result;
      });
    });
  };

  var getCallbackURL = function getCallbackURL() {
    var initialOptions = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    var defaultOptions = {
      ppx: 'wwp_',
      version: 2,
      status: 200,
      reason: 'OK',
      ticket: undefined,
      callbackURL: undefined,
      hw: false // hardware legacy

    };

    var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

    var url = options.callbackURL;
    var firstDelimiter = url.indexOf('?') === -1 ? '?' : '&';
    url += "".concat(firstDelimiter + encodeURIComponent(options.ppx), "version=").concat(options.version);
    url += "&".concat(encodeURIComponent(options.ppx), "ticket=").concat(encodeURIComponent(options.ticket));
    url += "&".concat(encodeURIComponent(options.ppx), "status=").concat(encodeURIComponent(options.status));
    url += "&".concat(encodeURIComponent(options.ppx), "reason=").concat(encodeURIComponent(options.reason));

    if (options.hw) {
      url += "&".concat(encodeURIComponent(options.ppx), "hw=1");
    }

    return url;
  };

  var getUniversalURL = function getUniversalURL() {
    var initialOptions = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    var allowCallbackURL = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
    var defaultOptions = {
      universal: false,
      operation: 'auth',
      ppx: 'wwp_',
      version: 2,
      ticket: undefined,
      callbackURL: undefined,
      clientKey: undefined
    };

    var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

    var url = options.universal ? 'https://get.wwpass.com/' : 'wwpass://';

    if (options.operation === 'auth') {
      url += 'auth';
      url += "?v=".concat(options.version);
      url += "&t=".concat(encodeURIComponent(options.ticket));
      url += "&ppx=".concat(encodeURIComponent(options.ppx));

      if (options.clientKey) {
        url += "&ck=".concat(options.clientKey);
      }

      if (options.callbackURL && allowCallbackURL) {
        url += "&c=".concat(encodeURIComponent(options.callbackURL));
      }
    } else {
      url += "".concat(encodeURIComponent(options.operation), "?t=").concat(encodeURIComponent(options.ticket));
    }

    return url;
  };

  var navigateToCallback = function navigateToCallback(options) {
    window.location.href = getCallbackURL(options);
  };

  // can-promise has a crash in some versions of react native that dont have
  // standard global objects
  // https://github.com/soldair/node-qrcode/issues/157

  var canPromise = function () {
    return typeof Promise === 'function' && Promise.prototype && Promise.prototype.then
  };

  var toString = {}.toString;

  var isarray = Array.isArray || function (arr) {
    return toString.call(arr) == '[object Array]';
  };

  function typedArraySupport () {
    // Can typed array instances be augmented?
    try {
      var arr = new Uint8Array(1);
      arr.__proto__ = {__proto__: Uint8Array.prototype, foo: function () { return 42 }};
      return arr.foo() === 42
    } catch (e) {
      return false
    }
  }

  Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport();

  var K_MAX_LENGTH = Buffer.TYPED_ARRAY_SUPPORT
      ? 0x7fffffff
      : 0x3fffffff;

  function Buffer (arg, offset, length) {
    if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
      return new Buffer(arg, offset, length)
    }

    if (typeof arg === 'number') {
      return allocUnsafe(this, arg)
    }

    return from(this, arg, offset, length)
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    Buffer.prototype.__proto__ = Uint8Array.prototype;
    Buffer.__proto__ = Uint8Array;

    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    if (typeof Symbol !== 'undefined' && Symbol.species &&
        Buffer[Symbol.species] === Buffer) {
      Object.defineProperty(Buffer, Symbol.species, {
        value: null,
        configurable: true,
        enumerable: false,
        writable: false
      });
    }
  }

  function checked (length) {
    // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
    // length is NaN (which is otherwise coerced to zero.)
    if (length >= K_MAX_LENGTH) {
      throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                           'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
    }
    return length | 0
  }

  function isnan (val) {
    return val !== val // eslint-disable-line no-self-compare
  }

  function createBuffer (that, length) {
    var buf;
    if (Buffer.TYPED_ARRAY_SUPPORT) {
      buf = new Uint8Array(length);
      buf.__proto__ = Buffer.prototype;
    } else {
      // Fallback: Return an object instance of the Buffer class
      buf = that;
      if (buf === null) {
        buf = new Buffer(length);
      }
      buf.length = length;
    }

    return buf
  }

  function allocUnsafe (that, size) {
    var buf = createBuffer(that, size < 0 ? 0 : checked(size) | 0);

    if (!Buffer.TYPED_ARRAY_SUPPORT) {
      for (var i = 0; i < size; ++i) {
        buf[i] = 0;
      }
    }

    return buf
  }

  function fromString (that, string) {
    var length = byteLength(string) | 0;
    var buf = createBuffer(that, length);

    var actual = buf.write(string);

    if (actual !== length) {
      // Writing a hex string, for example, that contains invalid characters will
      // cause everything after the first invalid character to be ignored. (e.g.
      // 'abxxcd' will be treated as 'ab')
      buf = buf.slice(0, actual);
    }

    return buf
  }

  function fromArrayLike (that, array) {
    var length = array.length < 0 ? 0 : checked(array.length) | 0;
    var buf = createBuffer(that, length);
    for (var i = 0; i < length; i += 1) {
      buf[i] = array[i] & 255;
    }
    return buf
  }

  function fromArrayBuffer (that, array, byteOffset, length) {
    if (byteOffset < 0 || array.byteLength < byteOffset) {
      throw new RangeError('\'offset\' is out of bounds')
    }

    if (array.byteLength < byteOffset + (length || 0)) {
      throw new RangeError('\'length\' is out of bounds')
    }

    var buf;
    if (byteOffset === undefined && length === undefined) {
      buf = new Uint8Array(array);
    } else if (length === undefined) {
      buf = new Uint8Array(array, byteOffset);
    } else {
      buf = new Uint8Array(array, byteOffset, length);
    }

    if (Buffer.TYPED_ARRAY_SUPPORT) {
      // Return an augmented `Uint8Array` instance, for best performance
      buf.__proto__ = Buffer.prototype;
    } else {
      // Fallback: Return an object instance of the Buffer class
      buf = fromArrayLike(that, buf);
    }

    return buf
  }

  function fromObject (that, obj) {
    if (Buffer.isBuffer(obj)) {
      var len = checked(obj.length) | 0;
      var buf = createBuffer(that, len);

      if (buf.length === 0) {
        return buf
      }

      obj.copy(buf, 0, 0, len);
      return buf
    }

    if (obj) {
      if ((typeof ArrayBuffer !== 'undefined' &&
          obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
        if (typeof obj.length !== 'number' || isnan(obj.length)) {
          return createBuffer(that, 0)
        }
        return fromArrayLike(that, obj)
      }

      if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
        return fromArrayLike(that, obj.data)
      }
    }

    throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
  }

  function utf8ToBytes (string, units) {
    units = units || Infinity;
    var codePoint;
    var length = string.length;
    var leadSurrogate = null;
    var bytes = [];

    for (var i = 0; i < length; ++i) {
      codePoint = string.charCodeAt(i);

      // is surrogate component
      if (codePoint > 0xD7FF && codePoint < 0xE000) {
        // last char was a lead
        if (!leadSurrogate) {
          // no lead yet
          if (codePoint > 0xDBFF) {
            // unexpected trail
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
            continue
          } else if (i + 1 === length) {
            // unpaired lead
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
            continue
          }

          // valid lead
          leadSurrogate = codePoint;

          continue
        }

        // 2 leads in a row
        if (codePoint < 0xDC00) {
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
          leadSurrogate = codePoint;
          continue
        }

        // valid surrogate pair
        codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000;
      } else if (leadSurrogate) {
        // valid bmp char, but last char was a lead
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
      }

      leadSurrogate = null;

      // encode utf8
      if (codePoint < 0x80) {
        if ((units -= 1) < 0) break
        bytes.push(codePoint);
      } else if (codePoint < 0x800) {
        if ((units -= 2) < 0) break
        bytes.push(
          codePoint >> 0x6 | 0xC0,
          codePoint & 0x3F | 0x80
        );
      } else if (codePoint < 0x10000) {
        if ((units -= 3) < 0) break
        bytes.push(
          codePoint >> 0xC | 0xE0,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        );
      } else if (codePoint < 0x110000) {
        if ((units -= 4) < 0) break
        bytes.push(
          codePoint >> 0x12 | 0xF0,
          codePoint >> 0xC & 0x3F | 0x80,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        );
      } else {
        throw new Error('Invalid code point')
      }
    }

    return bytes
  }

  function byteLength (string) {
    if (Buffer.isBuffer(string)) {
      return string.length
    }
    if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
        (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
      return string.byteLength
    }
    if (typeof string !== 'string') {
      string = '' + string;
    }

    var len = string.length;
    if (len === 0) return 0

    return utf8ToBytes(string).length
  }

  function blitBuffer (src, dst, offset, length) {
    for (var i = 0; i < length; ++i) {
      if ((i + offset >= dst.length) || (i >= src.length)) break
      dst[i + offset] = src[i];
    }
    return i
  }

  function utf8Write (buf, string, offset, length) {
    return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
  }

  function from (that, value, offset, length) {
    if (typeof value === 'number') {
      throw new TypeError('"value" argument must not be a number')
    }

    if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
      return fromArrayBuffer(that, value, offset, length)
    }

    if (typeof value === 'string') {
      return fromString(that, value)
    }

    return fromObject(that, value)
  }

  Buffer.prototype.write = function write (string, offset, length) {
    // Buffer#write(string)
    if (offset === undefined) {
      length = this.length;
      offset = 0;
    // Buffer#write(string, encoding)
    } else if (length === undefined && typeof offset === 'string') {
      length = this.length;
      offset = 0;
    // Buffer#write(string, offset[, length])
    } else if (isFinite(offset)) {
      offset = offset | 0;
      if (isFinite(length)) {
        length = length | 0;
      } else {
        length = undefined;
      }
    }

    var remaining = this.length - offset;
    if (length === undefined || length > remaining) length = remaining;

    if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
      throw new RangeError('Attempt to write outside buffer bounds')
    }

    return utf8Write(this, string, offset, length)
  };

  Buffer.prototype.slice = function slice (start, end) {
    var len = this.length;
    start = ~~start;
    end = end === undefined ? len : ~~end;

    if (start < 0) {
      start += len;
      if (start < 0) start = 0;
    } else if (start > len) {
      start = len;
    }

    if (end < 0) {
      end += len;
      if (end < 0) end = 0;
    } else if (end > len) {
      end = len;
    }

    if (end < start) end = start;

    var newBuf;
    if (Buffer.TYPED_ARRAY_SUPPORT) {
      newBuf = this.subarray(start, end);
      // Return an augmented `Uint8Array` instance
      newBuf.__proto__ = Buffer.prototype;
    } else {
      var sliceLen = end - start;
      newBuf = new Buffer(sliceLen, undefined);
      for (var i = 0; i < sliceLen; ++i) {
        newBuf[i] = this[i + start];
      }
    }

    return newBuf
  };

  Buffer.prototype.copy = function copy (target, targetStart, start, end) {
    if (!start) start = 0;
    if (!end && end !== 0) end = this.length;
    if (targetStart >= target.length) targetStart = target.length;
    if (!targetStart) targetStart = 0;
    if (end > 0 && end < start) end = start;

    // Copy 0 bytes; we're done
    if (end === start) return 0
    if (target.length === 0 || this.length === 0) return 0

    // Fatal error conditions
    if (targetStart < 0) {
      throw new RangeError('targetStart out of bounds')
    }
    if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
    if (end < 0) throw new RangeError('sourceEnd out of bounds')

    // Are we oob?
    if (end > this.length) end = this.length;
    if (target.length - targetStart < end - start) {
      end = target.length - targetStart + start;
    }

    var len = end - start;
    var i;

    if (this === target && start < targetStart && targetStart < end) {
      // descending copy from end
      for (i = len - 1; i >= 0; --i) {
        target[i + targetStart] = this[i + start];
      }
    } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
      // ascending copy from start
      for (i = 0; i < len; ++i) {
        target[i + targetStart] = this[i + start];
      }
    } else {
      Uint8Array.prototype.set.call(
        target,
        this.subarray(start, start + len),
        targetStart
      );
    }

    return len
  };

  Buffer.prototype.fill = function fill (val, start, end) {
    // Handle string cases:
    if (typeof val === 'string') {
      if (typeof start === 'string') {
        start = 0;
        end = this.length;
      } else if (typeof end === 'string') {
        end = this.length;
      }
      if (val.length === 1) {
        var code = val.charCodeAt(0);
        if (code < 256) {
          val = code;
        }
      }
    } else if (typeof val === 'number') {
      val = val & 255;
    }

    // Invalid ranges are not set to a default, so can range check early.
    if (start < 0 || this.length < start || this.length < end) {
      throw new RangeError('Out of range index')
    }

    if (end <= start) {
      return this
    }

    start = start >>> 0;
    end = end === undefined ? this.length : end >>> 0;

    if (!val) val = 0;

    var i;
    if (typeof val === 'number') {
      for (i = start; i < end; ++i) {
        this[i] = val;
      }
    } else {
      var bytes = Buffer.isBuffer(val)
        ? val
        : new Buffer(val);
      var len = bytes.length;
      for (i = 0; i < end - start; ++i) {
        this[i + start] = bytes[i % len];
      }
    }

    return this
  };

  Buffer.concat = function concat (list, length) {
    if (!isarray(list)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }

    if (list.length === 0) {
      return createBuffer(null, 0)
    }

    var i;
    if (length === undefined) {
      length = 0;
      for (i = 0; i < list.length; ++i) {
        length += list[i].length;
      }
    }

    var buffer = allocUnsafe(null, length);
    var pos = 0;
    for (i = 0; i < list.length; ++i) {
      var buf = list[i];
      if (!Buffer.isBuffer(buf)) {
        throw new TypeError('"list" argument must be an Array of Buffers')
      }
      buf.copy(buffer, pos);
      pos += buf.length;
    }
    return buffer
  };

  Buffer.byteLength = byteLength;

  Buffer.prototype._isBuffer = true;
  Buffer.isBuffer = function isBuffer (b) {
    return !!(b != null && b._isBuffer)
  };

  var alloc = function (size) {
    var buffer = new Buffer(size);
    buffer.fill(0);
    return buffer
  };

  var from_1 = function (data) {
    return new Buffer(data)
  };

  var typedarrayBuffer = {
  	alloc: alloc,
  	from: from_1
  };

  var toSJISFunction;
  var CODEWORDS_COUNT = [
    0, // Not used
    26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
    404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
    1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
    2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706
  ];

  /**
   * Returns the QR Code size for the specified version
   *
   * @param  {Number} version QR Code version
   * @return {Number}         size of QR code
   */
  var getSymbolSize = function getSymbolSize (version) {
    if (!version) throw new Error('"version" cannot be null or undefined')
    if (version < 1 || version > 40) throw new Error('"version" should be in range from 1 to 40')
    return version * 4 + 17
  };

  /**
   * Returns the total number of codewords used to store data and EC information.
   *
   * @param  {Number} version QR Code version
   * @return {Number}         Data length in bits
   */
  var getSymbolTotalCodewords = function getSymbolTotalCodewords (version) {
    return CODEWORDS_COUNT[version]
  };

  /**
   * Encode data with Bose-Chaudhuri-Hocquenghem
   *
   * @param  {Number} data Value to encode
   * @return {Number}      Encoded value
   */
  var getBCHDigit = function (data) {
    var digit = 0;

    while (data !== 0) {
      digit++;
      data >>>= 1;
    }

    return digit
  };

  var setToSJISFunction = function setToSJISFunction (f) {
    if (typeof f !== 'function') {
      throw new Error('"toSJISFunc" is not a valid function.')
    }

    toSJISFunction = f;
  };

  var isKanjiModeEnabled = function () {
    return typeof toSJISFunction !== 'undefined'
  };

  var toSJIS = function toSJIS (kanji) {
    return toSJISFunction(kanji)
  };

  var utils = {
  	getSymbolSize: getSymbolSize,
  	getSymbolTotalCodewords: getSymbolTotalCodewords,
  	getBCHDigit: getBCHDigit,
  	setToSJISFunction: setToSJISFunction,
  	isKanjiModeEnabled: isKanjiModeEnabled,
  	toSJIS: toSJIS
  };

  function createCommonjsModule(fn, module) {
  	return module = { exports: {} }, fn(module, module.exports), module.exports;
  }

  var errorCorrectionLevel = createCommonjsModule(function (module, exports) {
  exports.L = { bit: 1 };
  exports.M = { bit: 0 };
  exports.Q = { bit: 3 };
  exports.H = { bit: 2 };

  function fromString (string) {
    if (typeof string !== 'string') {
      throw new Error('Param is not a string')
    }

    var lcStr = string.toLowerCase();

    switch (lcStr) {
      case 'l':
      case 'low':
        return exports.L

      case 'm':
      case 'medium':
        return exports.M

      case 'q':
      case 'quartile':
        return exports.Q

      case 'h':
      case 'high':
        return exports.H

      default:
        throw new Error('Unknown EC Level: ' + string)
    }
  }

  exports.isValid = function isValid (level) {
    return level && typeof level.bit !== 'undefined' &&
      level.bit >= 0 && level.bit < 4
  };

  exports.from = function from (value, defaultValue) {
    if (exports.isValid(value)) {
      return value
    }

    try {
      return fromString(value)
    } catch (e) {
      return defaultValue
    }
  };
  });
  var errorCorrectionLevel_1 = errorCorrectionLevel.L;
  var errorCorrectionLevel_2 = errorCorrectionLevel.M;
  var errorCorrectionLevel_3 = errorCorrectionLevel.Q;
  var errorCorrectionLevel_4 = errorCorrectionLevel.H;
  var errorCorrectionLevel_5 = errorCorrectionLevel.isValid;

  function BitBuffer () {
    this.buffer = [];
    this.length = 0;
  }

  BitBuffer.prototype = {

    get: function (index) {
      var bufIndex = Math.floor(index / 8);
      return ((this.buffer[bufIndex] >>> (7 - index % 8)) & 1) === 1
    },

    put: function (num, length) {
      for (var i = 0; i < length; i++) {
        this.putBit(((num >>> (length - i - 1)) & 1) === 1);
      }
    },

    getLengthInBits: function () {
      return this.length
    },

    putBit: function (bit) {
      var bufIndex = Math.floor(this.length / 8);
      if (this.buffer.length <= bufIndex) {
        this.buffer.push(0);
      }

      if (bit) {
        this.buffer[bufIndex] |= (0x80 >>> (this.length % 8));
      }

      this.length++;
    }
  };

  var bitBuffer = BitBuffer;

  /**
   * Helper class to handle QR Code symbol modules
   *
   * @param {Number} size Symbol size
   */
  function BitMatrix (size) {
    if (!size || size < 1) {
      throw new Error('BitMatrix size must be defined and greater than 0')
    }

    this.size = size;
    this.data = typedarrayBuffer.alloc(size * size);
    this.reservedBit = typedarrayBuffer.alloc(size * size);
  }

  /**
   * Set bit value at specified location
   * If reserved flag is set, this bit will be ignored during masking process
   *
   * @param {Number}  row
   * @param {Number}  col
   * @param {Boolean} value
   * @param {Boolean} reserved
   */
  BitMatrix.prototype.set = function (row, col, value, reserved) {
    var index = row * this.size + col;
    this.data[index] = value;
    if (reserved) this.reservedBit[index] = true;
  };

  /**
   * Returns bit value at specified location
   *
   * @param  {Number}  row
   * @param  {Number}  col
   * @return {Boolean}
   */
  BitMatrix.prototype.get = function (row, col) {
    return this.data[row * this.size + col]
  };

  /**
   * Applies xor operator at specified location
   * (used during masking process)
   *
   * @param {Number}  row
   * @param {Number}  col
   * @param {Boolean} value
   */
  BitMatrix.prototype.xor = function (row, col, value) {
    this.data[row * this.size + col] ^= value;
  };

  /**
   * Check if bit at specified location is reserved
   *
   * @param {Number}   row
   * @param {Number}   col
   * @return {Boolean}
   */
  BitMatrix.prototype.isReserved = function (row, col) {
    return this.reservedBit[row * this.size + col]
  };

  var bitMatrix = BitMatrix;

  var alignmentPattern = createCommonjsModule(function (module, exports) {
  /**
   * Alignment pattern are fixed reference pattern in defined positions
   * in a matrix symbology, which enables the decode software to re-synchronise
   * the coordinate mapping of the image modules in the event of moderate amounts
   * of distortion of the image.
   *
   * Alignment patterns are present only in QR Code symbols of version 2 or larger
   * and their number depends on the symbol version.
   */

  var getSymbolSize = utils.getSymbolSize;

  /**
   * Calculate the row/column coordinates of the center module of each alignment pattern
   * for the specified QR Code version.
   *
   * The alignment patterns are positioned symmetrically on either side of the diagonal
   * running from the top left corner of the symbol to the bottom right corner.
   *
   * Since positions are simmetrical only half of the coordinates are returned.
   * Each item of the array will represent in turn the x and y coordinate.
   * @see {@link getPositions}
   *
   * @param  {Number} version QR Code version
   * @return {Array}          Array of coordinate
   */
  exports.getRowColCoords = function getRowColCoords (version) {
    if (version === 1) return []

    var posCount = Math.floor(version / 7) + 2;
    var size = getSymbolSize(version);
    var intervals = size === 145 ? 26 : Math.ceil((size - 13) / (2 * posCount - 2)) * 2;
    var positions = [size - 7]; // Last coord is always (size - 7)

    for (var i = 1; i < posCount - 1; i++) {
      positions[i] = positions[i - 1] - intervals;
    }

    positions.push(6); // First coord is always 6

    return positions.reverse()
  };

  /**
   * Returns an array containing the positions of each alignment pattern.
   * Each array's element represent the center point of the pattern as (x, y) coordinates
   *
   * Coordinates are calculated expanding the row/column coordinates returned by {@link getRowColCoords}
   * and filtering out the items that overlaps with finder pattern
   *
   * @example
   * For a Version 7 symbol {@link getRowColCoords} returns values 6, 22 and 38.
   * The alignment patterns, therefore, are to be centered on (row, column)
   * positions (6,22), (22,6), (22,22), (22,38), (38,22), (38,38).
   * Note that the coordinates (6,6), (6,38), (38,6) are occupied by finder patterns
   * and are not therefore used for alignment patterns.
   *
   * var pos = getPositions(7)
   * // [[6,22], [22,6], [22,22], [22,38], [38,22], [38,38]]
   *
   * @param  {Number} version QR Code version
   * @return {Array}          Array of coordinates
   */
  exports.getPositions = function getPositions (version) {
    var coords = [];
    var pos = exports.getRowColCoords(version);
    var posLength = pos.length;

    for (var i = 0; i < posLength; i++) {
      for (var j = 0; j < posLength; j++) {
        // Skip if position is occupied by finder patterns
        if ((i === 0 && j === 0) ||             // top-left
            (i === 0 && j === posLength - 1) || // bottom-left
            (i === posLength - 1 && j === 0)) { // top-right
          continue
        }

        coords.push([pos[i], pos[j]]);
      }
    }

    return coords
  };
  });
  var alignmentPattern_1 = alignmentPattern.getRowColCoords;
  var alignmentPattern_2 = alignmentPattern.getPositions;

  var getSymbolSize$1 = utils.getSymbolSize;
  var FINDER_PATTERN_SIZE = 7;

  /**
   * Returns an array containing the positions of each finder pattern.
   * Each array's element represent the top-left point of the pattern as (x, y) coordinates
   *
   * @param  {Number} version QR Code version
   * @return {Array}          Array of coordinates
   */
  var getPositions = function getPositions (version) {
    var size = getSymbolSize$1(version);

    return [
      // top-left
      [0, 0],
      // top-right
      [size - FINDER_PATTERN_SIZE, 0],
      // bottom-left
      [0, size - FINDER_PATTERN_SIZE]
    ]
  };

  var finderPattern = {
  	getPositions: getPositions
  };

  var maskPattern = createCommonjsModule(function (module, exports) {
  /**
   * Data mask pattern reference
   * @type {Object}
   */
  exports.Patterns = {
    PATTERN000: 0,
    PATTERN001: 1,
    PATTERN010: 2,
    PATTERN011: 3,
    PATTERN100: 4,
    PATTERN101: 5,
    PATTERN110: 6,
    PATTERN111: 7
  };

  /**
   * Weighted penalty scores for the undesirable features
   * @type {Object}
   */
  var PenaltyScores = {
    N1: 3,
    N2: 3,
    N3: 40,
    N4: 10
  };

  /**
   * Check if mask pattern value is valid
   *
   * @param  {Number}  mask    Mask pattern
   * @return {Boolean}         true if valid, false otherwise
   */
  exports.isValid = function isValid (mask) {
    return mask != null && mask !== '' && !isNaN(mask) && mask >= 0 && mask <= 7
  };

  /**
   * Returns mask pattern from a value.
   * If value is not valid, returns undefined
   *
   * @param  {Number|String} value        Mask pattern value
   * @return {Number}                     Valid mask pattern or undefined
   */
  exports.from = function from (value) {
    return exports.isValid(value) ? parseInt(value, 10) : undefined
  };

  /**
  * Find adjacent modules in row/column with the same color
  * and assign a penalty value.
  *
  * Points: N1 + i
  * i is the amount by which the number of adjacent modules of the same color exceeds 5
  */
  exports.getPenaltyN1 = function getPenaltyN1 (data) {
    var size = data.size;
    var points = 0;
    var sameCountCol = 0;
    var sameCountRow = 0;
    var lastCol = null;
    var lastRow = null;

    for (var row = 0; row < size; row++) {
      sameCountCol = sameCountRow = 0;
      lastCol = lastRow = null;

      for (var col = 0; col < size; col++) {
        var module = data.get(row, col);
        if (module === lastCol) {
          sameCountCol++;
        } else {
          if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
          lastCol = module;
          sameCountCol = 1;
        }

        module = data.get(col, row);
        if (module === lastRow) {
          sameCountRow++;
        } else {
          if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
          lastRow = module;
          sameCountRow = 1;
        }
      }

      if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
      if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
    }

    return points
  };

  /**
   * Find 2x2 blocks with the same color and assign a penalty value
   *
   * Points: N2 * (m - 1) * (n - 1)
   */
  exports.getPenaltyN2 = function getPenaltyN2 (data) {
    var size = data.size;
    var points = 0;

    for (var row = 0; row < size - 1; row++) {
      for (var col = 0; col < size - 1; col++) {
        var last = data.get(row, col) +
          data.get(row, col + 1) +
          data.get(row + 1, col) +
          data.get(row + 1, col + 1);

        if (last === 4 || last === 0) points++;
      }
    }

    return points * PenaltyScores.N2
  };

  /**
   * Find 1:1:3:1:1 ratio (dark:light:dark:light:dark) pattern in row/column,
   * preceded or followed by light area 4 modules wide
   *
   * Points: N3 * number of pattern found
   */
  exports.getPenaltyN3 = function getPenaltyN3 (data) {
    var size = data.size;
    var points = 0;
    var bitsCol = 0;
    var bitsRow = 0;

    for (var row = 0; row < size; row++) {
      bitsCol = bitsRow = 0;
      for (var col = 0; col < size; col++) {
        bitsCol = ((bitsCol << 1) & 0x7FF) | data.get(row, col);
        if (col >= 10 && (bitsCol === 0x5D0 || bitsCol === 0x05D)) points++;

        bitsRow = ((bitsRow << 1) & 0x7FF) | data.get(col, row);
        if (col >= 10 && (bitsRow === 0x5D0 || bitsRow === 0x05D)) points++;
      }
    }

    return points * PenaltyScores.N3
  };

  /**
   * Calculate proportion of dark modules in entire symbol
   *
   * Points: N4 * k
   *
   * k is the rating of the deviation of the proportion of dark modules
   * in the symbol from 50% in steps of 5%
   */
  exports.getPenaltyN4 = function getPenaltyN4 (data) {
    var darkCount = 0;
    var modulesCount = data.data.length;

    for (var i = 0; i < modulesCount; i++) darkCount += data.data[i];

    var k = Math.abs(Math.ceil((darkCount * 100 / modulesCount) / 5) - 10);

    return k * PenaltyScores.N4
  };

  /**
   * Return mask value at given position
   *
   * @param  {Number} maskPattern Pattern reference value
   * @param  {Number} i           Row
   * @param  {Number} j           Column
   * @return {Boolean}            Mask value
   */
  function getMaskAt (maskPattern, i, j) {
    switch (maskPattern) {
      case exports.Patterns.PATTERN000: return (i + j) % 2 === 0
      case exports.Patterns.PATTERN001: return i % 2 === 0
      case exports.Patterns.PATTERN010: return j % 3 === 0
      case exports.Patterns.PATTERN011: return (i + j) % 3 === 0
      case exports.Patterns.PATTERN100: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0
      case exports.Patterns.PATTERN101: return (i * j) % 2 + (i * j) % 3 === 0
      case exports.Patterns.PATTERN110: return ((i * j) % 2 + (i * j) % 3) % 2 === 0
      case exports.Patterns.PATTERN111: return ((i * j) % 3 + (i + j) % 2) % 2 === 0

      default: throw new Error('bad maskPattern:' + maskPattern)
    }
  }

  /**
   * Apply a mask pattern to a BitMatrix
   *
   * @param  {Number}    pattern Pattern reference number
   * @param  {BitMatrix} data    BitMatrix data
   */
  exports.applyMask = function applyMask (pattern, data) {
    var size = data.size;

    for (var col = 0; col < size; col++) {
      for (var row = 0; row < size; row++) {
        if (data.isReserved(row, col)) continue
        data.xor(row, col, getMaskAt(pattern, row, col));
      }
    }
  };

  /**
   * Returns the best mask pattern for data
   *
   * @param  {BitMatrix} data
   * @return {Number} Mask pattern reference number
   */
  exports.getBestMask = function getBestMask (data, setupFormatFunc) {
    var numPatterns = Object.keys(exports.Patterns).length;
    var bestPattern = 0;
    var lowerPenalty = Infinity;

    for (var p = 0; p < numPatterns; p++) {
      setupFormatFunc(p);
      exports.applyMask(p, data);

      // Calculate penalty
      var penalty =
        exports.getPenaltyN1(data) +
        exports.getPenaltyN2(data) +
        exports.getPenaltyN3(data) +
        exports.getPenaltyN4(data);

      // Undo previously applied mask
      exports.applyMask(p, data);

      if (penalty < lowerPenalty) {
        lowerPenalty = penalty;
        bestPattern = p;
      }
    }

    return bestPattern
  };
  });
  var maskPattern_1 = maskPattern.Patterns;
  var maskPattern_2 = maskPattern.isValid;
  var maskPattern_3 = maskPattern.getPenaltyN1;
  var maskPattern_4 = maskPattern.getPenaltyN2;
  var maskPattern_5 = maskPattern.getPenaltyN3;
  var maskPattern_6 = maskPattern.getPenaltyN4;
  var maskPattern_7 = maskPattern.applyMask;
  var maskPattern_8 = maskPattern.getBestMask;

  var EC_BLOCKS_TABLE = [
  // L  M  Q  H
    1, 1, 1, 1,
    1, 1, 1, 1,
    1, 1, 2, 2,
    1, 2, 2, 4,
    1, 2, 4, 4,
    2, 4, 4, 4,
    2, 4, 6, 5,
    2, 4, 6, 6,
    2, 5, 8, 8,
    4, 5, 8, 8,
    4, 5, 8, 11,
    4, 8, 10, 11,
    4, 9, 12, 16,
    4, 9, 16, 16,
    6, 10, 12, 18,
    6, 10, 17, 16,
    6, 11, 16, 19,
    6, 13, 18, 21,
    7, 14, 21, 25,
    8, 16, 20, 25,
    8, 17, 23, 25,
    9, 17, 23, 34,
    9, 18, 25, 30,
    10, 20, 27, 32,
    12, 21, 29, 35,
    12, 23, 34, 37,
    12, 25, 34, 40,
    13, 26, 35, 42,
    14, 28, 38, 45,
    15, 29, 40, 48,
    16, 31, 43, 51,
    17, 33, 45, 54,
    18, 35, 48, 57,
    19, 37, 51, 60,
    19, 38, 53, 63,
    20, 40, 56, 66,
    21, 43, 59, 70,
    22, 45, 62, 74,
    24, 47, 65, 77,
    25, 49, 68, 81
  ];

  var EC_CODEWORDS_TABLE = [
  // L  M  Q  H
    7, 10, 13, 17,
    10, 16, 22, 28,
    15, 26, 36, 44,
    20, 36, 52, 64,
    26, 48, 72, 88,
    36, 64, 96, 112,
    40, 72, 108, 130,
    48, 88, 132, 156,
    60, 110, 160, 192,
    72, 130, 192, 224,
    80, 150, 224, 264,
    96, 176, 260, 308,
    104, 198, 288, 352,
    120, 216, 320, 384,
    132, 240, 360, 432,
    144, 280, 408, 480,
    168, 308, 448, 532,
    180, 338, 504, 588,
    196, 364, 546, 650,
    224, 416, 600, 700,
    224, 442, 644, 750,
    252, 476, 690, 816,
    270, 504, 750, 900,
    300, 560, 810, 960,
    312, 588, 870, 1050,
    336, 644, 952, 1110,
    360, 700, 1020, 1200,
    390, 728, 1050, 1260,
    420, 784, 1140, 1350,
    450, 812, 1200, 1440,
    480, 868, 1290, 1530,
    510, 924, 1350, 1620,
    540, 980, 1440, 1710,
    570, 1036, 1530, 1800,
    570, 1064, 1590, 1890,
    600, 1120, 1680, 1980,
    630, 1204, 1770, 2100,
    660, 1260, 1860, 2220,
    720, 1316, 1950, 2310,
    750, 1372, 2040, 2430
  ];

  /**
   * Returns the number of error correction block that the QR Code should contain
   * for the specified version and error correction level.
   *
   * @param  {Number} version              QR Code version
   * @param  {Number} errorCorrectionLevel Error correction level
   * @return {Number}                      Number of error correction blocks
   */
  var getBlocksCount = function getBlocksCount (version, errorCorrectionLevel$1) {
    switch (errorCorrectionLevel$1) {
      case errorCorrectionLevel.L:
        return EC_BLOCKS_TABLE[(version - 1) * 4 + 0]
      case errorCorrectionLevel.M:
        return EC_BLOCKS_TABLE[(version - 1) * 4 + 1]
      case errorCorrectionLevel.Q:
        return EC_BLOCKS_TABLE[(version - 1) * 4 + 2]
      case errorCorrectionLevel.H:
        return EC_BLOCKS_TABLE[(version - 1) * 4 + 3]
      default:
        return undefined
    }
  };

  /**
   * Returns the number of error correction codewords to use for the specified
   * version and error correction level.
   *
   * @param  {Number} version              QR Code version
   * @param  {Number} errorCorrectionLevel Error correction level
   * @return {Number}                      Number of error correction codewords
   */
  var getTotalCodewordsCount = function getTotalCodewordsCount (version, errorCorrectionLevel$1) {
    switch (errorCorrectionLevel$1) {
      case errorCorrectionLevel.L:
        return EC_CODEWORDS_TABLE[(version - 1) * 4 + 0]
      case errorCorrectionLevel.M:
        return EC_CODEWORDS_TABLE[(version - 1) * 4 + 1]
      case errorCorrectionLevel.Q:
        return EC_CODEWORDS_TABLE[(version - 1) * 4 + 2]
      case errorCorrectionLevel.H:
        return EC_CODEWORDS_TABLE[(version - 1) * 4 + 3]
      default:
        return undefined
    }
  };

  var errorCorrectionCode = {
  	getBlocksCount: getBlocksCount,
  	getTotalCodewordsCount: getTotalCodewordsCount
  };

  var EXP_TABLE = typedarrayBuffer.alloc(512);
  var LOG_TABLE = typedarrayBuffer.alloc(256)
  /**
   * Precompute the log and anti-log tables for faster computation later
   *
   * For each possible value in the galois field 2^8, we will pre-compute
   * the logarithm and anti-logarithm (exponential) of this value
   *
   * ref {@link https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders#Introduction_to_mathematical_fields}
   */
  ;(function initTables () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP_TABLE[i] = x;
      LOG_TABLE[x] = i;

      x <<= 1; // multiply by 2

      // The QR code specification says to use byte-wise modulo 100011101 arithmetic.
      // This means that when a number is 256 or larger, it should be XORed with 0x11D.
      if (x & 0x100) { // similar to x >= 256, but a lot faster (because 0x100 == 256)
        x ^= 0x11D;
      }
    }

    // Optimization: double the size of the anti-log table so that we don't need to mod 255 to
    // stay inside the bounds (because we will mainly use this table for the multiplication of
    // two GF numbers, no more).
    // @see {@link mul}
    for (i = 255; i < 512; i++) {
      EXP_TABLE[i] = EXP_TABLE[i - 255];
    }
  }());

  /**
   * Returns log value of n inside Galois Field
   *
   * @param  {Number} n
   * @return {Number}
   */
  var log = function log (n) {
    if (n < 1) throw new Error('log(' + n + ')')
    return LOG_TABLE[n]
  };

  /**
   * Returns anti-log value of n inside Galois Field
   *
   * @param  {Number} n
   * @return {Number}
   */
  var exp = function exp (n) {
    return EXP_TABLE[n]
  };

  /**
   * Multiplies two number inside Galois Field
   *
   * @param  {Number} x
   * @param  {Number} y
   * @return {Number}
   */
  var mul = function mul (x, y) {
    if (x === 0 || y === 0) return 0

    // should be EXP_TABLE[(LOG_TABLE[x] + LOG_TABLE[y]) % 255] if EXP_TABLE wasn't oversized
    // @see {@link initTables}
    return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]]
  };

  var galoisField = {
  	log: log,
  	exp: exp,
  	mul: mul
  };

  var polynomial = createCommonjsModule(function (module, exports) {
  /**
   * Multiplies two polynomials inside Galois Field
   *
   * @param  {Buffer} p1 Polynomial
   * @param  {Buffer} p2 Polynomial
   * @return {Buffer}    Product of p1 and p2
   */
  exports.mul = function mul (p1, p2) {
    var coeff = typedarrayBuffer.alloc(p1.length + p2.length - 1);

    for (var i = 0; i < p1.length; i++) {
      for (var j = 0; j < p2.length; j++) {
        coeff[i + j] ^= galoisField.mul(p1[i], p2[j]);
      }
    }

    return coeff
  };

  /**
   * Calculate the remainder of polynomials division
   *
   * @param  {Buffer} divident Polynomial
   * @param  {Buffer} divisor  Polynomial
   * @return {Buffer}          Remainder
   */
  exports.mod = function mod (divident, divisor) {
    var result = typedarrayBuffer.from(divident);

    while ((result.length - divisor.length) >= 0) {
      var coeff = result[0];

      for (var i = 0; i < divisor.length; i++) {
        result[i] ^= galoisField.mul(divisor[i], coeff);
      }

      // remove all zeros from buffer head
      var offset = 0;
      while (offset < result.length && result[offset] === 0) offset++;
      result = result.slice(offset);
    }

    return result
  };

  /**
   * Generate an irreducible generator polynomial of specified degree
   * (used by Reed-Solomon encoder)
   *
   * @param  {Number} degree Degree of the generator polynomial
   * @return {Buffer}        Buffer containing polynomial coefficients
   */
  exports.generateECPolynomial = function generateECPolynomial (degree) {
    var poly = typedarrayBuffer.from([1]);
    for (var i = 0; i < degree; i++) {
      poly = exports.mul(poly, [1, galoisField.exp(i)]);
    }

    return poly
  };
  });
  var polynomial_1 = polynomial.mul;
  var polynomial_2 = polynomial.mod;
  var polynomial_3 = polynomial.generateECPolynomial;

  var byteLength_1 = byteLength$1;
  var toByteArray_1 = toByteArray;
  var fromByteArray_1 = fromByteArray;

  var lookup = [];
  var revLookup = [];
  var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array;

  var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (var i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i];
    revLookup[code.charCodeAt(i)] = i;
  }

  // Support decoding URL-safe base64 strings, as Node.js does.
  // See: https://en.wikipedia.org/wiki/Base64#URL_applications
  revLookup['-'.charCodeAt(0)] = 62;
  revLookup['_'.charCodeAt(0)] = 63;

  function getLens (b64) {
    var len = b64.length;

    if (len % 4 > 0) {
      throw new Error('Invalid string. Length must be a multiple of 4')
    }

    // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42
    var validLen = b64.indexOf('=');
    if (validLen === -1) validLen = len;

    var placeHoldersLen = validLen === len
      ? 0
      : 4 - (validLen % 4);

    return [validLen, placeHoldersLen]
  }

  // base64 is 4/3 + up to two characters of the original data
  function byteLength$1 (b64) {
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
  }

  function _byteLength (b64, validLen, placeHoldersLen) {
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
  }

  function toByteArray (b64) {
    var tmp;
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];

    var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));

    var curByte = 0;

    // if there are placeholders, only get up to the last complete 4 chars
    var len = placeHoldersLen > 0
      ? validLen - 4
      : validLen;

    var i;
    for (i = 0; i < len; i += 4) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 18) |
        (revLookup[b64.charCodeAt(i + 1)] << 12) |
        (revLookup[b64.charCodeAt(i + 2)] << 6) |
        revLookup[b64.charCodeAt(i + 3)];
      arr[curByte++] = (tmp >> 16) & 0xFF;
      arr[curByte++] = (tmp >> 8) & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 2) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 2) |
        (revLookup[b64.charCodeAt(i + 1)] >> 4);
      arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 1) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 10) |
        (revLookup[b64.charCodeAt(i + 1)] << 4) |
        (revLookup[b64.charCodeAt(i + 2)] >> 2);
      arr[curByte++] = (tmp >> 8) & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    return arr
  }

  function tripletToBase64 (num) {
    return lookup[num >> 18 & 0x3F] +
      lookup[num >> 12 & 0x3F] +
      lookup[num >> 6 & 0x3F] +
      lookup[num & 0x3F]
  }

  function encodeChunk (uint8, start, end) {
    var tmp;
    var output = [];
    for (var i = start; i < end; i += 3) {
      tmp =
        ((uint8[i] << 16) & 0xFF0000) +
        ((uint8[i + 1] << 8) & 0xFF00) +
        (uint8[i + 2] & 0xFF);
      output.push(tripletToBase64(tmp));
    }
    return output.join('')
  }

  function fromByteArray (uint8) {
    var tmp;
    var len = uint8.length;
    var extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
    var parts = [];
    var maxChunkLength = 16383; // must be multiple of 3

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
      parts.push(encodeChunk(
        uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
      ));
    }

    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
      tmp = uint8[len - 1];
      parts.push(
        lookup[tmp >> 2] +
        lookup[(tmp << 4) & 0x3F] +
        '=='
      );
    } else if (extraBytes === 2) {
      tmp = (uint8[len - 2] << 8) + uint8[len - 1];
      parts.push(
        lookup[tmp >> 10] +
        lookup[(tmp >> 4) & 0x3F] +
        lookup[(tmp << 2) & 0x3F] +
        '='
      );
    }

    return parts.join('')
  }

  var base64Js = {
  	byteLength: byteLength_1,
  	toByteArray: toByteArray_1,
  	fromByteArray: fromByteArray_1
  };

  var read = function (buffer, offset, isLE, mLen, nBytes) {
    var e, m;
    var eLen = (nBytes * 8) - mLen - 1;
    var eMax = (1 << eLen) - 1;
    var eBias = eMax >> 1;
    var nBits = -7;
    var i = isLE ? (nBytes - 1) : 0;
    var d = isLE ? -1 : 1;
    var s = buffer[offset + i];

    i += d;

    e = s & ((1 << (-nBits)) - 1);
    s >>= (-nBits);
    nBits += eLen;
    for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

    m = e & ((1 << (-nBits)) - 1);
    e >>= (-nBits);
    nBits += mLen;
    for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

    if (e === 0) {
      e = 1 - eBias;
    } else if (e === eMax) {
      return m ? NaN : ((s ? -1 : 1) * Infinity)
    } else {
      m = m + Math.pow(2, mLen);
      e = e - eBias;
    }
    return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
  };

  var write = function (buffer, value, offset, isLE, mLen, nBytes) {
    var e, m, c;
    var eLen = (nBytes * 8) - mLen - 1;
    var eMax = (1 << eLen) - 1;
    var eBias = eMax >> 1;
    var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0);
    var i = isLE ? 0 : (nBytes - 1);
    var d = isLE ? 1 : -1;
    var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

    value = Math.abs(value);

    if (isNaN(value) || value === Infinity) {
      m = isNaN(value) ? 1 : 0;
      e = eMax;
    } else {
      e = Math.floor(Math.log(value) / Math.LN2);
      if (value * (c = Math.pow(2, -e)) < 1) {
        e--;
        c *= 2;
      }
      if (e + eBias >= 1) {
        value += rt / c;
      } else {
        value += rt * Math.pow(2, 1 - eBias);
      }
      if (value * c >= 2) {
        e++;
        c /= 2;
      }

      if (e + eBias >= eMax) {
        m = 0;
        e = eMax;
      } else if (e + eBias >= 1) {
        m = ((value * c) - 1) * Math.pow(2, mLen);
        e = e + eBias;
      } else {
        m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
        e = 0;
      }
    }

    for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

    e = (e << mLen) | m;
    eLen += mLen;
    for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

    buffer[offset + i - d] |= s * 128;
  };

  var ieee754 = {
  	read: read,
  	write: write
  };

  var buffer = createCommonjsModule(function (module, exports) {



  var customInspectSymbol =
    (typeof Symbol === 'function' && typeof Symbol.for === 'function')
      ? Symbol.for('nodejs.util.inspect.custom')
      : null;

  exports.Buffer = Buffer;
  exports.SlowBuffer = SlowBuffer;
  exports.INSPECT_MAX_BYTES = 50;

  var K_MAX_LENGTH = 0x7fffffff;
  exports.kMaxLength = K_MAX_LENGTH;

  /**
   * If `Buffer.TYPED_ARRAY_SUPPORT`:
   *   === true    Use Uint8Array implementation (fastest)
   *   === false   Print warning and recommend using `buffer` v4.x which has an Object
   *               implementation (most compatible, even IE6)
   *
   * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
   * Opera 11.6+, iOS 4.2+.
   *
   * We report that the browser does not support typed arrays if the are not subclassable
   * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
   * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
   * for __proto__ and has a buggy typed array implementation.
   */
  Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport();

  if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
      typeof console.error === 'function') {
    console.error(
      'This browser lacks typed array (Uint8Array) support which is required by ' +
      '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
    );
  }

  function typedArraySupport () {
    // Can typed array instances can be augmented?
    try {
      var arr = new Uint8Array(1);
      var proto = { foo: function () { return 42 } };
      Object.setPrototypeOf(proto, Uint8Array.prototype);
      Object.setPrototypeOf(arr, proto);
      return arr.foo() === 42
    } catch (e) {
      return false
    }
  }

  Object.defineProperty(Buffer.prototype, 'parent', {
    enumerable: true,
    get: function () {
      if (!Buffer.isBuffer(this)) return undefined
      return this.buffer
    }
  });

  Object.defineProperty(Buffer.prototype, 'offset', {
    enumerable: true,
    get: function () {
      if (!Buffer.isBuffer(this)) return undefined
      return this.byteOffset
    }
  });

  function createBuffer (length) {
    if (length > K_MAX_LENGTH) {
      throw new RangeError('The value "' + length + '" is invalid for option "size"')
    }
    // Return an augmented `Uint8Array` instance
    var buf = new Uint8Array(length);
    Object.setPrototypeOf(buf, Buffer.prototype);
    return buf
  }

  /**
   * The Buffer constructor returns instances of `Uint8Array` that have their
   * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
   * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
   * and the `Uint8Array` methods. Square bracket notation works as expected -- it
   * returns a single octet.
   *
   * The `Uint8Array` prototype remains unmodified.
   */

  function Buffer (arg, encodingOrOffset, length) {
    // Common case.
    if (typeof arg === 'number') {
      if (typeof encodingOrOffset === 'string') {
        throw new TypeError(
          'The "string" argument must be of type string. Received type number'
        )
      }
      return allocUnsafe(arg)
    }
    return from(arg, encodingOrOffset, length)
  }

  // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
  if (typeof Symbol !== 'undefined' && Symbol.species != null &&
      Buffer[Symbol.species] === Buffer) {
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true,
      enumerable: false,
      writable: false
    });
  }

  Buffer.poolSize = 8192; // not used by this implementation

  function from (value, encodingOrOffset, length) {
    if (typeof value === 'string') {
      return fromString(value, encodingOrOffset)
    }

    if (ArrayBuffer.isView(value)) {
      return fromArrayLike(value)
    }

    if (value == null) {
      throw new TypeError(
        'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
        'or Array-like Object. Received type ' + (typeof value)
      )
    }

    if (isInstance(value, ArrayBuffer) ||
        (value && isInstance(value.buffer, ArrayBuffer))) {
      return fromArrayBuffer(value, encodingOrOffset, length)
    }

    if (typeof value === 'number') {
      throw new TypeError(
        'The "value" argument must not be of type number. Received type number'
      )
    }

    var valueOf = value.valueOf && value.valueOf();
    if (valueOf != null && valueOf !== value) {
      return Buffer.from(valueOf, encodingOrOffset, length)
    }

    var b = fromObject(value);
    if (b) return b

    if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
        typeof value[Symbol.toPrimitive] === 'function') {
      return Buffer.from(
        value[Symbol.toPrimitive]('string'), encodingOrOffset, length
      )
    }

    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  /**
   * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
   * if value is a number.
   * Buffer.from(str[, encoding])
   * Buffer.from(array)
   * Buffer.from(buffer)
   * Buffer.from(arrayBuffer[, byteOffset[, length]])
   **/
  Buffer.from = function (value, encodingOrOffset, length) {
    return from(value, encodingOrOffset, length)
  };

  // Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
  // https://github.com/feross/buffer/pull/148
  Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype);
  Object.setPrototypeOf(Buffer, Uint8Array);

  function assertSize (size) {
    if (typeof size !== 'number') {
      throw new TypeError('"size" argument must be of type number')
    } else if (size < 0) {
      throw new RangeError('The value "' + size + '" is invalid for option "size"')
    }
  }

  function alloc (size, fill, encoding) {
    assertSize(size);
    if (size <= 0) {
      return createBuffer(size)
    }
    if (fill !== undefined) {
      // Only pay attention to encoding if it's a string. This
      // prevents accidentally sending in a number that would
      // be interpretted as a start offset.
      return typeof encoding === 'string'
        ? createBuffer(size).fill(fill, encoding)
        : createBuffer(size).fill(fill)
    }
    return createBuffer(size)
  }

  /**
   * Creates a new filled Buffer instance.
   * alloc(size[, fill[, encoding]])
   **/
  Buffer.alloc = function (size, fill, encoding) {
    return alloc(size, fill, encoding)
  };

  function allocUnsafe (size) {
    assertSize(size);
    return createBuffer(size < 0 ? 0 : checked(size) | 0)
  }

  /**
   * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
   * */
  Buffer.allocUnsafe = function (size) {
    return allocUnsafe(size)
  };
  /**
   * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
   */
  Buffer.allocUnsafeSlow = function (size) {
    return allocUnsafe(size)
  };

  function fromString (string, encoding) {
    if (typeof encoding !== 'string' || encoding === '') {
      encoding = 'utf8';
    }

    if (!Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }

    var length = byteLength(string, encoding) | 0;
    var buf = createBuffer(length);

    var actual = buf.write(string, encoding);

    if (actual !== length) {
      // Writing a hex string, for example, that contains invalid characters will
      // cause everything after the first invalid character to be ignored. (e.g.
      // 'abxxcd' will be treated as 'ab')
      buf = buf.slice(0, actual);
    }

    return buf
  }

  function fromArrayLike (array) {
    var length = array.length < 0 ? 0 : checked(array.length) | 0;
    var buf = createBuffer(length);
    for (var i = 0; i < length; i += 1) {
      buf[i] = array[i] & 255;
    }
    return buf
  }

  function fromArrayBuffer (array, byteOffset, length) {
    if (byteOffset < 0 || array.byteLength < byteOffset) {
      throw new RangeError('"offset" is outside of buffer bounds')
    }

    if (array.byteLength < byteOffset + (length || 0)) {
      throw new RangeError('"length" is outside of buffer bounds')
    }

    var buf;
    if (byteOffset === undefined && length === undefined) {
      buf = new Uint8Array(array);
    } else if (length === undefined) {
      buf = new Uint8Array(array, byteOffset);
    } else {
      buf = new Uint8Array(array, byteOffset, length);
    }

    // Return an augmented `Uint8Array` instance
    Object.setPrototypeOf(buf, Buffer.prototype);

    return buf
  }

  function fromObject (obj) {
    if (Buffer.isBuffer(obj)) {
      var len = checked(obj.length) | 0;
      var buf = createBuffer(len);

      if (buf.length === 0) {
        return buf
      }

      obj.copy(buf, 0, 0, len);
      return buf
    }

    if (obj.length !== undefined) {
      if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
        return createBuffer(0)
      }
      return fromArrayLike(obj)
    }

    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      return fromArrayLike(obj.data)
    }
  }

  function checked (length) {
    // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
    // length is NaN (which is otherwise coerced to zero.)
    if (length >= K_MAX_LENGTH) {
      throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                           'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
    }
    return length | 0
  }

  function SlowBuffer (length) {
    if (+length != length) { // eslint-disable-line eqeqeq
      length = 0;
    }
    return Buffer.alloc(+length)
  }

  Buffer.isBuffer = function isBuffer (b) {
    return b != null && b._isBuffer === true &&
      b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
  };

  Buffer.compare = function compare (a, b) {
    if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength);
    if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength);
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
      throw new TypeError(
        'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
      )
    }

    if (a === b) return 0

    var x = a.length;
    var y = b.length;

    for (var i = 0, len = Math.min(x, y); i < len; ++i) {
      if (a[i] !== b[i]) {
        x = a[i];
        y = b[i];
        break
      }
    }

    if (x < y) return -1
    if (y < x) return 1
    return 0
  };

  Buffer.isEncoding = function isEncoding (encoding) {
    switch (String(encoding).toLowerCase()) {
      case 'hex':
      case 'utf8':
      case 'utf-8':
      case 'ascii':
      case 'latin1':
      case 'binary':
      case 'base64':
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return true
      default:
        return false
    }
  };

  Buffer.concat = function concat (list, length) {
    if (!Array.isArray(list)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }

    if (list.length === 0) {
      return Buffer.alloc(0)
    }

    var i;
    if (length === undefined) {
      length = 0;
      for (i = 0; i < list.length; ++i) {
        length += list[i].length;
      }
    }

    var buffer = Buffer.allocUnsafe(length);
    var pos = 0;
    for (i = 0; i < list.length; ++i) {
      var buf = list[i];
      if (isInstance(buf, Uint8Array)) {
        buf = Buffer.from(buf);
      }
      if (!Buffer.isBuffer(buf)) {
        throw new TypeError('"list" argument must be an Array of Buffers')
      }
      buf.copy(buffer, pos);
      pos += buf.length;
    }
    return buffer
  };

  function byteLength (string, encoding) {
    if (Buffer.isBuffer(string)) {
      return string.length
    }
    if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
      return string.byteLength
    }
    if (typeof string !== 'string') {
      throw new TypeError(
        'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
        'Received type ' + typeof string
      )
    }

    var len = string.length;
    var mustMatch = (arguments.length > 2 && arguments[2] === true);
    if (!mustMatch && len === 0) return 0

    // Use a for loop to avoid recursion
    var loweredCase = false;
    for (;;) {
      switch (encoding) {
        case 'ascii':
        case 'latin1':
        case 'binary':
          return len
        case 'utf8':
        case 'utf-8':
          return utf8ToBytes(string).length
        case 'ucs2':
        case 'ucs-2':
        case 'utf16le':
        case 'utf-16le':
          return len * 2
        case 'hex':
          return len >>> 1
        case 'base64':
          return base64ToBytes(string).length
        default:
          if (loweredCase) {
            return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
          }
          encoding = ('' + encoding).toLowerCase();
          loweredCase = true;
      }
    }
  }
  Buffer.byteLength = byteLength;

  function slowToString (encoding, start, end) {
    var loweredCase = false;

    // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
    // property of a typed array.

    // This behaves neither like String nor Uint8Array in that we set start/end
    // to their upper/lower bounds if the value passed is out of range.
    // undefined is handled specially as per ECMA-262 6th Edition,
    // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
    if (start === undefined || start < 0) {
      start = 0;
    }
    // Return early if start > this.length. Done here to prevent potential uint32
    // coercion fail below.
    if (start > this.length) {
      return ''
    }

    if (end === undefined || end > this.length) {
      end = this.length;
    }

    if (end <= 0) {
      return ''
    }

    // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
    end >>>= 0;
    start >>>= 0;

    if (end <= start) {
      return ''
    }

    if (!encoding) encoding = 'utf8';

    while (true) {
      switch (encoding) {
        case 'hex':
          return hexSlice(this, start, end)

        case 'utf8':
        case 'utf-8':
          return utf8Slice(this, start, end)

        case 'ascii':
          return asciiSlice(this, start, end)

        case 'latin1':
        case 'binary':
          return latin1Slice(this, start, end)

        case 'base64':
          return base64Slice(this, start, end)

        case 'ucs2':
        case 'ucs-2':
        case 'utf16le':
        case 'utf-16le':
          return utf16leSlice(this, start, end)

        default:
          if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
          encoding = (encoding + '').toLowerCase();
          loweredCase = true;
      }
    }
  }

  // This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
  // to detect a Buffer instance. It's not possible to use `instanceof Buffer`
  // reliably in a browserify context because there could be multiple different
  // copies of the 'buffer' package in use. This method works even for Buffer
  // instances that were created from another copy of the `buffer` package.
  // See: https://github.com/feross/buffer/issues/154
  Buffer.prototype._isBuffer = true;

  function swap (b, n, m) {
    var i = b[n];
    b[n] = b[m];
    b[m] = i;
  }

  Buffer.prototype.swap16 = function swap16 () {
    var len = this.length;
    if (len % 2 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 16-bits')
    }
    for (var i = 0; i < len; i += 2) {
      swap(this, i, i + 1);
    }
    return this
  };

  Buffer.prototype.swap32 = function swap32 () {
    var len = this.length;
    if (len % 4 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 32-bits')
    }
    for (var i = 0; i < len; i += 4) {
      swap(this, i, i + 3);
      swap(this, i + 1, i + 2);
    }
    return this
  };

  Buffer.prototype.swap64 = function swap64 () {
    var len = this.length;
    if (len % 8 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 64-bits')
    }
    for (var i = 0; i < len; i += 8) {
      swap(this, i, i + 7);
      swap(this, i + 1, i + 6);
      swap(this, i + 2, i + 5);
      swap(this, i + 3, i + 4);
    }
    return this
  };

  Buffer.prototype.toString = function toString () {
    var length = this.length;
    if (length === 0) return ''
    if (arguments.length === 0) return utf8Slice(this, 0, length)
    return slowToString.apply(this, arguments)
  };

  Buffer.prototype.toLocaleString = Buffer.prototype.toString;

  Buffer.prototype.equals = function equals (b) {
    if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
    if (this === b) return true
    return Buffer.compare(this, b) === 0
  };

  Buffer.prototype.inspect = function inspect () {
    var str = '';
    var max = exports.INSPECT_MAX_BYTES;
    str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim();
    if (this.length > max) str += ' ... ';
    return '<Buffer ' + str + '>'
  };
  if (customInspectSymbol) {
    Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect;
  }

  Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
    if (isInstance(target, Uint8Array)) {
      target = Buffer.from(target, target.offset, target.byteLength);
    }
    if (!Buffer.isBuffer(target)) {
      throw new TypeError(
        'The "target" argument must be one of type Buffer or Uint8Array. ' +
        'Received type ' + (typeof target)
      )
    }

    if (start === undefined) {
      start = 0;
    }
    if (end === undefined) {
      end = target ? target.length : 0;
    }
    if (thisStart === undefined) {
      thisStart = 0;
    }
    if (thisEnd === undefined) {
      thisEnd = this.length;
    }

    if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
      throw new RangeError('out of range index')
    }

    if (thisStart >= thisEnd && start >= end) {
      return 0
    }
    if (thisStart >= thisEnd) {
      return -1
    }
    if (start >= end) {
      return 1
    }

    start >>>= 0;
    end >>>= 0;
    thisStart >>>= 0;
    thisEnd >>>= 0;

    if (this === target) return 0

    var x = thisEnd - thisStart;
    var y = end - start;
    var len = Math.min(x, y);

    var thisCopy = this.slice(thisStart, thisEnd);
    var targetCopy = target.slice(start, end);

    for (var i = 0; i < len; ++i) {
      if (thisCopy[i] !== targetCopy[i]) {
        x = thisCopy[i];
        y = targetCopy[i];
        break
      }
    }

    if (x < y) return -1
    if (y < x) return 1
    return 0
  };

  // Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
  // OR the last index of `val` in `buffer` at offset <= `byteOffset`.
  //
  // Arguments:
  // - buffer - a Buffer to search
  // - val - a string, Buffer, or number
  // - byteOffset - an index into `buffer`; will be clamped to an int32
  // - encoding - an optional encoding, relevant is val is a string
  // - dir - true for indexOf, false for lastIndexOf
  function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
    // Empty buffer means no match
    if (buffer.length === 0) return -1

    // Normalize byteOffset
    if (typeof byteOffset === 'string') {
      encoding = byteOffset;
      byteOffset = 0;
    } else if (byteOffset > 0x7fffffff) {
      byteOffset = 0x7fffffff;
    } else if (byteOffset < -0x80000000) {
      byteOffset = -0x80000000;
    }
    byteOffset = +byteOffset; // Coerce to Number.
    if (numberIsNaN(byteOffset)) {
      // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
      byteOffset = dir ? 0 : (buffer.length - 1);
    }

    // Normalize byteOffset: negative offsets start from the end of the buffer
    if (byteOffset < 0) byteOffset = buffer.length + byteOffset;
    if (byteOffset >= buffer.length) {
      if (dir) return -1
      else byteOffset = buffer.length - 1;
    } else if (byteOffset < 0) {
      if (dir) byteOffset = 0;
      else return -1
    }

    // Normalize val
    if (typeof val === 'string') {
      val = Buffer.from(val, encoding);
    }

    // Finally, search either indexOf (if dir is true) or lastIndexOf
    if (Buffer.isBuffer(val)) {
      // Special case: looking for empty string/buffer always fails
      if (val.length === 0) {
        return -1
      }
      return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
    } else if (typeof val === 'number') {
      val = val & 0xFF; // Search for a byte value [0-255]
      if (typeof Uint8Array.prototype.indexOf === 'function') {
        if (dir) {
          return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
        } else {
          return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
        }
      }
      return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
    }

    throw new TypeError('val must be string, number or Buffer')
  }

  function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
    var indexSize = 1;
    var arrLength = arr.length;
    var valLength = val.length;

    if (encoding !== undefined) {
      encoding = String(encoding).toLowerCase();
      if (encoding === 'ucs2' || encoding === 'ucs-2' ||
          encoding === 'utf16le' || encoding === 'utf-16le') {
        if (arr.length < 2 || val.length < 2) {
          return -1
        }
        indexSize = 2;
        arrLength /= 2;
        valLength /= 2;
        byteOffset /= 2;
      }
    }

    function read (buf, i) {
      if (indexSize === 1) {
        return buf[i]
      } else {
        return buf.readUInt16BE(i * indexSize)
      }
    }

    var i;
    if (dir) {
      var foundIndex = -1;
      for (i = byteOffset; i < arrLength; i++) {
        if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
          if (foundIndex === -1) foundIndex = i;
          if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
        } else {
          if (foundIndex !== -1) i -= i - foundIndex;
          foundIndex = -1;
        }
      }
    } else {
      if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;
      for (i = byteOffset; i >= 0; i--) {
        var found = true;
        for (var j = 0; j < valLength; j++) {
          if (read(arr, i + j) !== read(val, j)) {
            found = false;
            break
          }
        }
        if (found) return i
      }
    }

    return -1
  }

  Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
    return this.indexOf(val, byteOffset, encoding) !== -1
  };

  Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
    return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
  };

  Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
    return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
  };

  function hexWrite (buf, string, offset, length) {
    offset = Number(offset) || 0;
    var remaining = buf.length - offset;
    if (!length) {
      length = remaining;
    } else {
      length = Number(length);
      if (length > remaining) {
        length = remaining;
      }
    }

    var strLen = string.length;

    if (length > strLen / 2) {
      length = strLen / 2;
    }
    for (var i = 0; i < length; ++i) {
      var parsed = parseInt(string.substr(i * 2, 2), 16);
      if (numberIsNaN(parsed)) return i
      buf[offset + i] = parsed;
    }
    return i
  }

  function utf8Write (buf, string, offset, length) {
    return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
  }

  function asciiWrite (buf, string, offset, length) {
    return blitBuffer(asciiToBytes(string), buf, offset, length)
  }

  function latin1Write (buf, string, offset, length) {
    return asciiWrite(buf, string, offset, length)
  }

  function base64Write (buf, string, offset, length) {
    return blitBuffer(base64ToBytes(string), buf, offset, length)
  }

  function ucs2Write (buf, string, offset, length) {
    return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
  }

  Buffer.prototype.write = function write (string, offset, length, encoding) {
    // Buffer#write(string)
    if (offset === undefined) {
      encoding = 'utf8';
      length = this.length;
      offset = 0;
    // Buffer#write(string, encoding)
    } else if (length === undefined && typeof offset === 'string') {
      encoding = offset;
      length = this.length;
      offset = 0;
    // Buffer#write(string, offset[, length][, encoding])
    } else if (isFinite(offset)) {
      offset = offset >>> 0;
      if (isFinite(length)) {
        length = length >>> 0;
        if (encoding === undefined) encoding = 'utf8';
      } else {
        encoding = length;
        length = undefined;
      }
    } else {
      throw new Error(
        'Buffer.write(string, encoding, offset[, length]) is no longer supported'
      )
    }

    var remaining = this.length - offset;
    if (length === undefined || length > remaining) length = remaining;

    if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
      throw new RangeError('Attempt to write outside buffer bounds')
    }

    if (!encoding) encoding = 'utf8';

    var loweredCase = false;
    for (;;) {
      switch (encoding) {
        case 'hex':
          return hexWrite(this, string, offset, length)

        case 'utf8':
        case 'utf-8':
          return utf8Write(this, string, offset, length)

        case 'ascii':
          return asciiWrite(this, string, offset, length)

        case 'latin1':
        case 'binary':
          return latin1Write(this, string, offset, length)

        case 'base64':
          // Warning: maxLength not taken into account in base64Write
          return base64Write(this, string, offset, length)

        case 'ucs2':
        case 'ucs-2':
        case 'utf16le':
        case 'utf-16le':
          return ucs2Write(this, string, offset, length)

        default:
          if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
          encoding = ('' + encoding).toLowerCase();
          loweredCase = true;
      }
    }
  };

  Buffer.prototype.toJSON = function toJSON () {
    return {
      type: 'Buffer',
      data: Array.prototype.slice.call(this._arr || this, 0)
    }
  };

  function base64Slice (buf, start, end) {
    if (start === 0 && end === buf.length) {
      return base64Js.fromByteArray(buf)
    } else {
      return base64Js.fromByteArray(buf.slice(start, end))
    }
  }

  function utf8Slice (buf, start, end) {
    end = Math.min(buf.length, end);
    var res = [];

    var i = start;
    while (i < end) {
      var firstByte = buf[i];
      var codePoint = null;
      var bytesPerSequence = (firstByte > 0xEF) ? 4
        : (firstByte > 0xDF) ? 3
          : (firstByte > 0xBF) ? 2
            : 1;

      if (i + bytesPerSequence <= end) {
        var secondByte, thirdByte, fourthByte, tempCodePoint;

        switch (bytesPerSequence) {
          case 1:
            if (firstByte < 0x80) {
              codePoint = firstByte;
            }
            break
          case 2:
            secondByte = buf[i + 1];
            if ((secondByte & 0xC0) === 0x80) {
              tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F);
              if (tempCodePoint > 0x7F) {
                codePoint = tempCodePoint;
              }
            }
            break
          case 3:
            secondByte = buf[i + 1];
            thirdByte = buf[i + 2];
            if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
              tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F);
              if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
                codePoint = tempCodePoint;
              }
            }
            break
          case 4:
            secondByte = buf[i + 1];
            thirdByte = buf[i + 2];
            fourthByte = buf[i + 3];
            if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
              tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F);
              if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
                codePoint = tempCodePoint;
              }
            }
        }
      }

      if (codePoint === null) {
        // we did not generate a valid codePoint so insert a
        // replacement char (U+FFFD) and advance only 1 byte
        codePoint = 0xFFFD;
        bytesPerSequence = 1;
      } else if (codePoint > 0xFFFF) {
        // encode to utf16 (surrogate pair dance)
        codePoint -= 0x10000;
        res.push(codePoint >>> 10 & 0x3FF | 0xD800);
        codePoint = 0xDC00 | codePoint & 0x3FF;
      }

      res.push(codePoint);
      i += bytesPerSequence;
    }

    return decodeCodePointsArray(res)
  }

  // Based on http://stackoverflow.com/a/22747272/680742, the browser with
  // the lowest limit is Chrome, with 0x10000 args.
  // We go 1 magnitude less, for safety
  var MAX_ARGUMENTS_LENGTH = 0x1000;

  function decodeCodePointsArray (codePoints) {
    var len = codePoints.length;
    if (len <= MAX_ARGUMENTS_LENGTH) {
      return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
    }

    // Decode in chunks to avoid "call stack size exceeded".
    var res = '';
    var i = 0;
    while (i < len) {
      res += String.fromCharCode.apply(
        String,
        codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
      );
    }
    return res
  }

  function asciiSlice (buf, start, end) {
    var ret = '';
    end = Math.min(buf.length, end);

    for (var i = start; i < end; ++i) {
      ret += String.fromCharCode(buf[i] & 0x7F);
    }
    return ret
  }

  function latin1Slice (buf, start, end) {
    var ret = '';
    end = Math.min(buf.length, end);

    for (var i = start; i < end; ++i) {
      ret += String.fromCharCode(buf[i]);
    }
    return ret
  }

  function hexSlice (buf, start, end) {
    var len = buf.length;

    if (!start || start < 0) start = 0;
    if (!end || end < 0 || end > len) end = len;

    var out = '';
    for (var i = start; i < end; ++i) {
      out += hexSliceLookupTable[buf[i]];
    }
    return out
  }

  function utf16leSlice (buf, start, end) {
    var bytes = buf.slice(start, end);
    var res = '';
    for (var i = 0; i < bytes.length; i += 2) {
      res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256));
    }
    return res
  }

  Buffer.prototype.slice = function slice (start, end) {
    var len = this.length;
    start = ~~start;
    end = end === undefined ? len : ~~end;

    if (start < 0) {
      start += len;
      if (start < 0) start = 0;
    } else if (start > len) {
      start = len;
    }

    if (end < 0) {
      end += len;
      if (end < 0) end = 0;
    } else if (end > len) {
      end = len;
    }

    if (end < start) end = start;

    var newBuf = this.subarray(start, end);
    // Return an augmented `Uint8Array` instance
    Object.setPrototypeOf(newBuf, Buffer.prototype);

    return newBuf
  };

  /*
   * Need to make sure that buffer isn't trying to write out of bounds.
   */
  function checkOffset (offset, ext, length) {
    if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
    if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
  }

  Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) checkOffset(offset, byteLength, this.length);

    var val = this[offset];
    var mul = 1;
    var i = 0;
    while (++i < byteLength && (mul *= 0x100)) {
      val += this[offset + i] * mul;
    }

    return val
  };

  Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) {
      checkOffset(offset, byteLength, this.length);
    }

    var val = this[offset + --byteLength];
    var mul = 1;
    while (byteLength > 0 && (mul *= 0x100)) {
      val += this[offset + --byteLength] * mul;
    }

    return val
  };

  Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 1, this.length);
    return this[offset]
  };

  Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 2, this.length);
    return this[offset] | (this[offset + 1] << 8)
  };

  Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 2, this.length);
    return (this[offset] << 8) | this[offset + 1]
  };

  Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);

    return ((this[offset]) |
        (this[offset + 1] << 8) |
        (this[offset + 2] << 16)) +
        (this[offset + 3] * 0x1000000)
  };

  Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);

    return (this[offset] * 0x1000000) +
      ((this[offset + 1] << 16) |
      (this[offset + 2] << 8) |
      this[offset + 3])
  };

  Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) checkOffset(offset, byteLength, this.length);

    var val = this[offset];
    var mul = 1;
    var i = 0;
    while (++i < byteLength && (mul *= 0x100)) {
      val += this[offset + i] * mul;
    }
    mul *= 0x80;

    if (val >= mul) val -= Math.pow(2, 8 * byteLength);

    return val
  };

  Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) checkOffset(offset, byteLength, this.length);

    var i = byteLength;
    var mul = 1;
    var val = this[offset + --i];
    while (i > 0 && (mul *= 0x100)) {
      val += this[offset + --i] * mul;
    }
    mul *= 0x80;

    if (val >= mul) val -= Math.pow(2, 8 * byteLength);

    return val
  };

  Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 1, this.length);
    if (!(this[offset] & 0x80)) return (this[offset])
    return ((0xff - this[offset] + 1) * -1)
  };

  Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 2, this.length);
    var val = this[offset] | (this[offset + 1] << 8);
    return (val & 0x8000) ? val | 0xFFFF0000 : val
  };

  Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 2, this.length);
    var val = this[offset + 1] | (this[offset] << 8);
    return (val & 0x8000) ? val | 0xFFFF0000 : val
  };

  Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);

    return (this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16) |
      (this[offset + 3] << 24)
  };

  Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);

    return (this[offset] << 24) |
      (this[offset + 1] << 16) |
      (this[offset + 2] << 8) |
      (this[offset + 3])
  };

  Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);
    return ieee754.read(this, offset, true, 23, 4)
  };

  Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 4, this.length);
    return ieee754.read(this, offset, false, 23, 4)
  };

  Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 8, this.length);
    return ieee754.read(this, offset, true, 52, 8)
  };

  Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
    offset = offset >>> 0;
    if (!noAssert) checkOffset(offset, 8, this.length);
    return ieee754.read(this, offset, false, 52, 8)
  };

  function checkInt (buf, value, offset, ext, max, min) {
    if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
    if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
    if (offset + ext > buf.length) throw new RangeError('Index out of range')
  }

  Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
    value = +value;
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) {
      var maxBytes = Math.pow(2, 8 * byteLength) - 1;
      checkInt(this, value, offset, byteLength, maxBytes, 0);
    }

    var mul = 1;
    var i = 0;
    this[offset] = value & 0xFF;
    while (++i < byteLength && (mul *= 0x100)) {
      this[offset + i] = (value / mul) & 0xFF;
    }

    return offset + byteLength
  };

  Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
    value = +value;
    offset = offset >>> 0;
    byteLength = byteLength >>> 0;
    if (!noAssert) {
      var maxBytes = Math.pow(2, 8 * byteLength) - 1;
      checkInt(this, value, offset, byteLength, maxBytes, 0);
    }

    var i = byteLength - 1;
    var mul = 1;
    this[offset + i] = value & 0xFF;
    while (--i >= 0 && (mul *= 0x100)) {
      this[offset + i] = (value / mul) & 0xFF;
    }

    return offset + byteLength
  };

  Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0);
    this[offset] = (value & 0xff);
    return offset + 1
  };

  Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);
    this[offset] = (value & 0xff);
    this[offset + 1] = (value >>> 8);
    return offset + 2
  };

  Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);
    this[offset] = (value >>> 8);
    this[offset + 1] = (value & 0xff);
    return offset + 2
  };

  Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);
    this[offset + 3] = (value >>> 24);
    this[offset + 2] = (value >>> 16);
    this[offset + 1] = (value >>> 8);
    this[offset] = (value & 0xff);
    return offset + 4
  };

  Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);
    this[offset] = (value >>> 24);
    this[offset + 1] = (value >>> 16);
    this[offset + 2] = (value >>> 8);
    this[offset + 3] = (value & 0xff);
    return offset + 4
  };

  Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      var limit = Math.pow(2, (8 * byteLength) - 1);

      checkInt(this, value, offset, byteLength, limit - 1, -limit);
    }

    var i = 0;
    var mul = 1;
    var sub = 0;
    this[offset] = value & 0xFF;
    while (++i < byteLength && (mul *= 0x100)) {
      if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
        sub = 1;
      }
      this[offset + i] = ((value / mul) >> 0) - sub & 0xFF;
    }

    return offset + byteLength
  };

  Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      var limit = Math.pow(2, (8 * byteLength) - 1);

      checkInt(this, value, offset, byteLength, limit - 1, -limit);
    }

    var i = byteLength - 1;
    var mul = 1;
    var sub = 0;
    this[offset + i] = value & 0xFF;
    while (--i >= 0 && (mul *= 0x100)) {
      if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
        sub = 1;
      }
      this[offset + i] = ((value / mul) >> 0) - sub & 0xFF;
    }

    return offset + byteLength
  };

  Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80);
    if (value < 0) value = 0xff + value + 1;
    this[offset] = (value & 0xff);
    return offset + 1
  };

  Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);
    this[offset] = (value & 0xff);
    this[offset + 1] = (value >>> 8);
    return offset + 2
  };

  Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);
    this[offset] = (value >>> 8);
    this[offset + 1] = (value & 0xff);
    return offset + 2
  };

  Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);
    this[offset] = (value & 0xff);
    this[offset + 1] = (value >>> 8);
    this[offset + 2] = (value >>> 16);
    this[offset + 3] = (value >>> 24);
    return offset + 4
  };

  Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);
    if (value < 0) value = 0xffffffff + value + 1;
    this[offset] = (value >>> 24);
    this[offset + 1] = (value >>> 16);
    this[offset + 2] = (value >>> 8);
    this[offset + 3] = (value & 0xff);
    return offset + 4
  };

  function checkIEEE754 (buf, value, offset, ext, max, min) {
    if (offset + ext > buf.length) throw new RangeError('Index out of range')
    if (offset < 0) throw new RangeError('Index out of range')
  }

  function writeFloat (buf, value, offset, littleEndian, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      checkIEEE754(buf, value, offset, 4);
    }
    ieee754.write(buf, value, offset, littleEndian, 23, 4);
    return offset + 4
  }

  Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
    return writeFloat(this, value, offset, true, noAssert)
  };

  Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
    return writeFloat(this, value, offset, false, noAssert)
  };

  function writeDouble (buf, value, offset, littleEndian, noAssert) {
    value = +value;
    offset = offset >>> 0;
    if (!noAssert) {
      checkIEEE754(buf, value, offset, 8);
    }
    ieee754.write(buf, value, offset, littleEndian, 52, 8);
    return offset + 8
  }

  Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
    return writeDouble(this, value, offset, true, noAssert)
  };

  Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
    return writeDouble(this, value, offset, false, noAssert)
  };

  // copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
  Buffer.prototype.copy = function copy (target, targetStart, start, end) {
    if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
    if (!start) start = 0;
    if (!end && end !== 0) end = this.length;
    if (targetStart >= target.length) targetStart = target.length;
    if (!targetStart) targetStart = 0;
    if (end > 0 && end < start) end = start;

    // Copy 0 bytes; we're done
    if (end === start) return 0
    if (target.length === 0 || this.length === 0) return 0

    // Fatal error conditions
    if (targetStart < 0) {
      throw new RangeError('targetStart out of bounds')
    }
    if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
    if (end < 0) throw new RangeError('sourceEnd out of bounds')

    // Are we oob?
    if (end > this.length) end = this.length;
    if (target.length - targetStart < end - start) {
      end = target.length - targetStart + start;
    }

    var len = end - start;

    if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
      // Use built-in when available, missing from IE11
      this.copyWithin(targetStart, start, end);
    } else if (this === target && start < targetStart && targetStart < end) {
      // descending copy from end
      for (var i = len - 1; i >= 0; --i) {
        target[i + targetStart] = this[i + start];
      }
    } else {
      Uint8Array.prototype.set.call(
        target,
        this.subarray(start, end),
        targetStart
      );
    }

    return len
  };

  // Usage:
  //    buffer.fill(number[, offset[, end]])
  //    buffer.fill(buffer[, offset[, end]])
  //    buffer.fill(string[, offset[, end]][, encoding])
  Buffer.prototype.fill = function fill (val, start, end, encoding) {
    // Handle string cases:
    if (typeof val === 'string') {
      if (typeof start === 'string') {
        encoding = start;
        start = 0;
        end = this.length;
      } else if (typeof end === 'string') {
        encoding = end;
        end = this.length;
      }
      if (encoding !== undefined && typeof encoding !== 'string') {
        throw new TypeError('encoding must be a string')
      }
      if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
        throw new TypeError('Unknown encoding: ' + encoding)
      }
      if (val.length === 1) {
        var code = val.charCodeAt(0);
        if ((encoding === 'utf8' && code < 128) ||
            encoding === 'latin1') {
          // Fast path: If `val` fits into a single byte, use that numeric value.
          val = code;
        }
      }
    } else if (typeof val === 'number') {
      val = val & 255;
    } else if (typeof val === 'boolean') {
      val = Number(val);
    }

    // Invalid ranges are not set to a default, so can range check early.
    if (start < 0 || this.length < start || this.length < end) {
      throw new RangeError('Out of range index')
    }

    if (end <= start) {
      return this
    }

    start = start >>> 0;
    end = end === undefined ? this.length : end >>> 0;

    if (!val) val = 0;

    var i;
    if (typeof val === 'number') {
      for (i = start; i < end; ++i) {
        this[i] = val;
      }
    } else {
      var bytes = Buffer.isBuffer(val)
        ? val
        : Buffer.from(val, encoding);
      var len = bytes.length;
      if (len === 0) {
        throw new TypeError('The value "' + val +
          '" is invalid for argument "value"')
      }
      for (i = 0; i < end - start; ++i) {
        this[i + start] = bytes[i % len];
      }
    }

    return this
  };

  // HELPER FUNCTIONS
  // ================

  var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g;

  function base64clean (str) {
    // Node takes equal signs as end of the Base64 encoding
    str = str.split('=')[0];
    // Node strips out invalid characters like \n and \t from the string, base64-js does not
    str = str.trim().replace(INVALID_BASE64_RE, '');
    // Node converts strings with length < 2 to ''
    if (str.length < 2) return ''
    // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
    while (str.length % 4 !== 0) {
      str = str + '=';
    }
    return str
  }

  function utf8ToBytes (string, units) {
    units = units || Infinity;
    var codePoint;
    var length = string.length;
    var leadSurrogate = null;
    var bytes = [];

    for (var i = 0; i < length; ++i) {
      codePoint = string.charCodeAt(i);

      // is surrogate component
      if (codePoint > 0xD7FF && codePoint < 0xE000) {
        // last char was a lead
        if (!leadSurrogate) {
          // no lead yet
          if (codePoint > 0xDBFF) {
            // unexpected trail
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
            continue
          } else if (i + 1 === length) {
            // unpaired lead
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
            continue
          }

          // valid lead
          leadSurrogate = codePoint;

          continue
        }

        // 2 leads in a row
        if (codePoint < 0xDC00) {
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
          leadSurrogate = codePoint;
          continue
        }

        // valid surrogate pair
        codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000;
      } else if (leadSurrogate) {
        // valid bmp char, but last char was a lead
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD);
      }

      leadSurrogate = null;

      // encode utf8
      if (codePoint < 0x80) {
        if ((units -= 1) < 0) break
        bytes.push(codePoint);
      } else if (codePoint < 0x800) {
        if ((units -= 2) < 0) break
        bytes.push(
          codePoint >> 0x6 | 0xC0,
          codePoint & 0x3F | 0x80
        );
      } else if (codePoint < 0x10000) {
        if ((units -= 3) < 0) break
        bytes.push(
          codePoint >> 0xC | 0xE0,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        );
      } else if (codePoint < 0x110000) {
        if ((units -= 4) < 0) break
        bytes.push(
          codePoint >> 0x12 | 0xF0,
          codePoint >> 0xC & 0x3F | 0x80,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        );
      } else {
        throw new Error('Invalid code point')
      }
    }

    return bytes
  }

  function asciiToBytes (str) {
    var byteArray = [];
    for (var i = 0; i < str.length; ++i) {
      // Node's code seems to be doing this and not & 0x7F..
      byteArray.push(str.charCodeAt(i) & 0xFF);
    }
    return byteArray
  }

  function utf16leToBytes (str, units) {
    var c, hi, lo;
    var byteArray = [];
    for (var i = 0; i < str.length; ++i) {
      if ((units -= 2) < 0) break

      c = str.charCodeAt(i);
      hi = c >> 8;
      lo = c % 256;
      byteArray.push(lo);
      byteArray.push(hi);
    }

    return byteArray
  }

  function base64ToBytes (str) {
    return base64Js.toByteArray(base64clean(str))
  }

  function blitBuffer (src, dst, offset, length) {
    for (var i = 0; i < length; ++i) {
      if ((i + offset >= dst.length) || (i >= src.length)) break
      dst[i + offset] = src[i];
    }
    return i
  }

  // ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
  // the `instanceof` check but they should be treated as of that type.
  // See: https://github.com/feross/buffer/issues/166
  function isInstance (obj, type) {
    return obj instanceof type ||
      (obj != null && obj.constructor != null && obj.constructor.name != null &&
        obj.constructor.name === type.name)
  }
  function numberIsNaN (obj) {
    // For IE11 support
    return obj !== obj // eslint-disable-line no-self-compare
  }

  // Create lookup table for `toString('hex')`
  // See: https://github.com/feross/buffer/issues/219
  var hexSliceLookupTable = (function () {
    var alphabet = '0123456789abcdef';
    var table = new Array(256);
    for (var i = 0; i < 16; ++i) {
      var i16 = i * 16;
      for (var j = 0; j < 16; ++j) {
        table[i16 + j] = alphabet[i] + alphabet[j];
      }
    }
    return table
  })();
  });
  var buffer_1 = buffer.Buffer;
  var buffer_2 = buffer.SlowBuffer;
  var buffer_3 = buffer.INSPECT_MAX_BYTES;
  var buffer_4 = buffer.kMaxLength;

  var Buffer$1 = buffer.Buffer;

  function ReedSolomonEncoder (degree) {
    this.genPoly = undefined;
    this.degree = degree;

    if (this.degree) this.initialize(this.degree);
  }

  /**
   * Initialize the encoder.
   * The input param should correspond to the number of error correction codewords.
   *
   * @param  {Number} degree
   */
  ReedSolomonEncoder.prototype.initialize = function initialize (degree) {
    // create an irreducible generator polynomial
    this.degree = degree;
    this.genPoly = polynomial.generateECPolynomial(this.degree);
  };

  /**
   * Encodes a chunk of data
   *
   * @param  {Buffer} data Buffer containing input data
   * @return {Buffer}      Buffer containing encoded data
   */
  ReedSolomonEncoder.prototype.encode = function encode (data) {
    if (!this.genPoly) {
      throw new Error('Encoder not initialized')
    }

    // Calculate EC for this data block
    // extends data size to data+genPoly size
    var pad = typedarrayBuffer.alloc(this.degree);
    var paddedData = Buffer$1.concat([data, pad], data.length + this.degree);

    // The error correction codewords are the remainder after dividing the data codewords
    // by a generator polynomial
    var remainder = polynomial.mod(paddedData, this.genPoly);

    // return EC data blocks (last n byte, where n is the degree of genPoly)
    // If coefficients number in remainder are less than genPoly degree,
    // pad with 0s to the left to reach the needed number of coefficients
    var start = this.degree - remainder.length;
    if (start > 0) {
      var buff = typedarrayBuffer.alloc(this.degree);
      remainder.copy(buff, start);

      return buff
    }

    return remainder
  };

  var reedSolomonEncoder = ReedSolomonEncoder;

  /**
   * Check if QR Code version is valid
   *
   * @param  {Number}  version QR Code version
   * @return {Boolean}         true if valid version, false otherwise
   */
  var isValid = function isValid (version) {
    return !isNaN(version) && version >= 1 && version <= 40
  };

  var versionCheck = {
  	isValid: isValid
  };

  var numeric = '[0-9]+';
  var alphanumeric = '[A-Z $%*+\\-./:]+';
  var kanji = '(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|' +
    '[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|' +
    '[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|' +
    '[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+';
  kanji = kanji.replace(/u/g, '\\u');

  var byte = '(?:(?![A-Z0-9 $%*+\\-./:]|' + kanji + ')(?:.|[\r\n]))+';

  var KANJI = new RegExp(kanji, 'g');
  var BYTE_KANJI = new RegExp('[^A-Z0-9 $%*+\\-./:]+', 'g');
  var BYTE = new RegExp(byte, 'g');
  var NUMERIC = new RegExp(numeric, 'g');
  var ALPHANUMERIC = new RegExp(alphanumeric, 'g');

  var TEST_KANJI = new RegExp('^' + kanji + '$');
  var TEST_NUMERIC = new RegExp('^' + numeric + '$');
  var TEST_ALPHANUMERIC = new RegExp('^[A-Z0-9 $%*+\\-./:]+$');

  var testKanji = function testKanji (str) {
    return TEST_KANJI.test(str)
  };

  var testNumeric = function testNumeric (str) {
    return TEST_NUMERIC.test(str)
  };

  var testAlphanumeric = function testAlphanumeric (str) {
    return TEST_ALPHANUMERIC.test(str)
  };

  var regex = {
  	KANJI: KANJI,
  	BYTE_KANJI: BYTE_KANJI,
  	BYTE: BYTE,
  	NUMERIC: NUMERIC,
  	ALPHANUMERIC: ALPHANUMERIC,
  	testKanji: testKanji,
  	testNumeric: testNumeric,
  	testAlphanumeric: testAlphanumeric
  };

  var mode = createCommonjsModule(function (module, exports) {
  /**
   * Numeric mode encodes data from the decimal digit set (0 - 9)
   * (byte values 30HEX to 39HEX).
   * Normally, 3 data characters are represented by 10 bits.
   *
   * @type {Object}
   */
  exports.NUMERIC = {
    id: 'Numeric',
    bit: 1 << 0,
    ccBits: [10, 12, 14]
  };

  /**
   * Alphanumeric mode encodes data from a set of 45 characters,
   * i.e. 10 numeric digits (0 - 9),
   *      26 alphabetic characters (A - Z),
   *   and 9 symbols (SP, $, %, *, +, -, ., /, :).
   * Normally, two input characters are represented by 11 bits.
   *
   * @type {Object}
   */
  exports.ALPHANUMERIC = {
    id: 'Alphanumeric',
    bit: 1 << 1,
    ccBits: [9, 11, 13]
  };

  /**
   * In byte mode, data is encoded at 8 bits per character.
   *
   * @type {Object}
   */
  exports.BYTE = {
    id: 'Byte',
    bit: 1 << 2,
    ccBits: [8, 16, 16]
  };

  /**
   * The Kanji mode efficiently encodes Kanji characters in accordance with
   * the Shift JIS system based on JIS X 0208.
   * The Shift JIS values are shifted from the JIS X 0208 values.
   * JIS X 0208 gives details of the shift coded representation.
   * Each two-byte character value is compacted to a 13-bit binary codeword.
   *
   * @type {Object}
   */
  exports.KANJI = {
    id: 'Kanji',
    bit: 1 << 3,
    ccBits: [8, 10, 12]
  };

  /**
   * Mixed mode will contain a sequences of data in a combination of any of
   * the modes described above
   *
   * @type {Object}
   */
  exports.MIXED = {
    bit: -1
  };

  /**
   * Returns the number of bits needed to store the data length
   * according to QR Code specifications.
   *
   * @param  {Mode}   mode    Data mode
   * @param  {Number} version QR Code version
   * @return {Number}         Number of bits
   */
  exports.getCharCountIndicator = function getCharCountIndicator (mode, version) {
    if (!mode.ccBits) throw new Error('Invalid mode: ' + mode)

    if (!versionCheck.isValid(version)) {
      throw new Error('Invalid version: ' + version)
    }

    if (version >= 1 && version < 10) return mode.ccBits[0]
    else if (version < 27) return mode.ccBits[1]
    return mode.ccBits[2]
  };

  /**
   * Returns the most efficient mode to store the specified data
   *
   * @param  {String} dataStr Input data string
   * @return {Mode}           Best mode
   */
  exports.getBestModeForData = function getBestModeForData (dataStr) {
    if (regex.testNumeric(dataStr)) return exports.NUMERIC
    else if (regex.testAlphanumeric(dataStr)) return exports.ALPHANUMERIC
    else if (regex.testKanji(dataStr)) return exports.KANJI
    else return exports.BYTE
  };

  /**
   * Return mode name as string
   *
   * @param {Mode} mode Mode object
   * @returns {String}  Mode name
   */
  exports.toString = function toString (mode) {
    if (mode && mode.id) return mode.id
    throw new Error('Invalid mode')
  };

  /**
   * Check if input param is a valid mode object
   *
   * @param   {Mode}    mode Mode object
   * @returns {Boolean} True if valid mode, false otherwise
   */
  exports.isValid = function isValid (mode) {
    return mode && mode.bit && mode.ccBits
  };

  /**
   * Get mode object from its name
   *
   * @param   {String} string Mode name
   * @returns {Mode}          Mode object
   */
  function fromString (string) {
    if (typeof string !== 'string') {
      throw new Error('Param is not a string')
    }

    var lcStr = string.toLowerCase();

    switch (lcStr) {
      case 'numeric':
        return exports.NUMERIC
      case 'alphanumeric':
        return exports.ALPHANUMERIC
      case 'kanji':
        return exports.KANJI
      case 'byte':
        return exports.BYTE
      default:
        throw new Error('Unknown mode: ' + string)
    }
  }

  /**
   * Returns mode from a value.
   * If value is not a valid mode, returns defaultValue
   *
   * @param  {Mode|String} value        Encoding mode
   * @param  {Mode}        defaultValue Fallback value
   * @return {Mode}                     Encoding mode
   */
  exports.from = function from (value, defaultValue) {
    if (exports.isValid(value)) {
      return value
    }

    try {
      return fromString(value)
    } catch (e) {
      return defaultValue
    }
  };
  });
  var mode_1 = mode.NUMERIC;
  var mode_2 = mode.ALPHANUMERIC;
  var mode_3 = mode.BYTE;
  var mode_4 = mode.KANJI;
  var mode_5 = mode.MIXED;
  var mode_6 = mode.getCharCountIndicator;
  var mode_7 = mode.getBestModeForData;
  var mode_8 = mode.isValid;

  var version = createCommonjsModule(function (module, exports) {
  // Generator polynomial used to encode version information
  var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
  var G18_BCH = utils.getBCHDigit(G18);

  function getBestVersionForDataLength (mode, length, errorCorrectionLevel) {
    for (var currentVersion = 1; currentVersion <= 40; currentVersion++) {
      if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, mode)) {
        return currentVersion
      }
    }

    return undefined
  }

  function getReservedBitsCount (mode$1, version) {
    // Character count indicator + mode indicator bits
    return mode.getCharCountIndicator(mode$1, version) + 4
  }

  function getTotalBitsFromDataArray (segments, version) {
    var totalBits = 0;

    segments.forEach(function (data) {
      var reservedBits = getReservedBitsCount(data.mode, version);
      totalBits += reservedBits + data.getBitsLength();
    });

    return totalBits
  }

  function getBestVersionForMixedData (segments, errorCorrectionLevel) {
    for (var currentVersion = 1; currentVersion <= 40; currentVersion++) {
      var length = getTotalBitsFromDataArray(segments, currentVersion);
      if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, mode.MIXED)) {
        return currentVersion
      }
    }

    return undefined
  }

  /**
   * Returns version number from a value.
   * If value is not a valid version, returns defaultValue
   *
   * @param  {Number|String} value        QR Code version
   * @param  {Number}        defaultValue Fallback value
   * @return {Number}                     QR Code version number
   */
  exports.from = function from (value, defaultValue) {
    if (versionCheck.isValid(value)) {
      return parseInt(value, 10)
    }

    return defaultValue
  };

  /**
   * Returns how much data can be stored with the specified QR code version
   * and error correction level
   *
   * @param  {Number} version              QR Code version (1-40)
   * @param  {Number} errorCorrectionLevel Error correction level
   * @param  {Mode}   mode                 Data mode
   * @return {Number}                      Quantity of storable data
   */
  exports.getCapacity = function getCapacity (version, errorCorrectionLevel, mode$1) {
    if (!versionCheck.isValid(version)) {
      throw new Error('Invalid QR Code version')
    }

    // Use Byte mode as default
    if (typeof mode$1 === 'undefined') mode$1 = mode.BYTE;

    // Total codewords for this QR code version (Data + Error correction)
    var totalCodewords = utils.getSymbolTotalCodewords(version);

    // Total number of error correction codewords
    var ecTotalCodewords = errorCorrectionCode.getTotalCodewordsCount(version, errorCorrectionLevel);

    // Total number of data codewords
    var dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;

    if (mode$1 === mode.MIXED) return dataTotalCodewordsBits

    var usableBits = dataTotalCodewordsBits - getReservedBitsCount(mode$1, version);

    // Return max number of storable codewords
    switch (mode$1) {
      case mode.NUMERIC:
        return Math.floor((usableBits / 10) * 3)

      case mode.ALPHANUMERIC:
        return Math.floor((usableBits / 11) * 2)

      case mode.KANJI:
        return Math.floor(usableBits / 13)

      case mode.BYTE:
      default:
        return Math.floor(usableBits / 8)
    }
  };

  /**
   * Returns the minimum version needed to contain the amount of data
   *
   * @param  {Segment} data                    Segment of data
   * @param  {Number} [errorCorrectionLevel=H] Error correction level
   * @param  {Mode} mode                       Data mode
   * @return {Number}                          QR Code version
   */
  exports.getBestVersionForData = function getBestVersionForData (data, errorCorrectionLevel$1) {
    var seg;

    var ecl = errorCorrectionLevel.from(errorCorrectionLevel$1, errorCorrectionLevel.M);

    if (isarray(data)) {
      if (data.length > 1) {
        return getBestVersionForMixedData(data, ecl)
      }

      if (data.length === 0) {
        return 1
      }

      seg = data[0];
    } else {
      seg = data;
    }

    return getBestVersionForDataLength(seg.mode, seg.getLength(), ecl)
  };

  /**
   * Returns version information with relative error correction bits
   *
   * The version information is included in QR Code symbols of version 7 or larger.
   * It consists of an 18-bit sequence containing 6 data bits,
   * with 12 error correction bits calculated using the (18, 6) Golay code.
   *
   * @param  {Number} version QR Code version
   * @return {Number}         Encoded version info bits
   */
  exports.getEncodedBits = function getEncodedBits (version) {
    if (!versionCheck.isValid(version) || version < 7) {
      throw new Error('Invalid QR Code version')
    }

    var d = version << 12;

    while (utils.getBCHDigit(d) - G18_BCH >= 0) {
      d ^= (G18 << (utils.getBCHDigit(d) - G18_BCH));
    }

    return (version << 12) | d
  };
  });
  var version_1 = version.getCapacity;
  var version_2 = version.getBestVersionForData;
  var version_3 = version.getEncodedBits;

  var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
  var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);
  var G15_BCH = utils.getBCHDigit(G15);

  /**
   * Returns format information with relative error correction bits
   *
   * The format information is a 15-bit sequence containing 5 data bits,
   * with 10 error correction bits calculated using the (15, 5) BCH code.
   *
   * @param  {Number} errorCorrectionLevel Error correction level
   * @param  {Number} mask                 Mask pattern
   * @return {Number}                      Encoded format information bits
   */
  var getEncodedBits = function getEncodedBits (errorCorrectionLevel, mask) {
    var data = ((errorCorrectionLevel.bit << 3) | mask);
    var d = data << 10;

    while (utils.getBCHDigit(d) - G15_BCH >= 0) {
      d ^= (G15 << (utils.getBCHDigit(d) - G15_BCH));
    }

    // xor final data with mask pattern in order to ensure that
    // no combination of Error Correction Level and data mask pattern
    // will result in an all-zero data string
    return ((data << 10) | d) ^ G15_MASK
  };

  var formatInfo = {
  	getEncodedBits: getEncodedBits
  };

  function NumericData (data) {
    this.mode = mode.NUMERIC;
    this.data = data.toString();
  }

  NumericData.getBitsLength = function getBitsLength (length) {
    return 10 * Math.floor(length / 3) + ((length % 3) ? ((length % 3) * 3 + 1) : 0)
  };

  NumericData.prototype.getLength = function getLength () {
    return this.data.length
  };

  NumericData.prototype.getBitsLength = function getBitsLength () {
    return NumericData.getBitsLength(this.data.length)
  };

  NumericData.prototype.write = function write (bitBuffer) {
    var i, group, value;

    // The input data string is divided into groups of three digits,
    // and each group is converted to its 10-bit binary equivalent.
    for (i = 0; i + 3 <= this.data.length; i += 3) {
      group = this.data.substr(i, 3);
      value = parseInt(group, 10);

      bitBuffer.put(value, 10);
    }

    // If the number of input digits is not an exact multiple of three,
    // the final one or two digits are converted to 4 or 7 bits respectively.
    var remainingNum = this.data.length - i;
    if (remainingNum > 0) {
      group = this.data.substr(i);
      value = parseInt(group, 10);

      bitBuffer.put(value, remainingNum * 3 + 1);
    }
  };

  var numericData = NumericData;

  /**
   * Array of characters available in alphanumeric mode
   *
   * As per QR Code specification, to each character
   * is assigned a value from 0 to 44 which in this case coincides
   * with the array index
   *
   * @type {Array}
   */
  var ALPHA_NUM_CHARS = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ' ', '$', '%', '*', '+', '-', '.', '/', ':'
  ];

  function AlphanumericData (data) {
    this.mode = mode.ALPHANUMERIC;
    this.data = data;
  }

  AlphanumericData.getBitsLength = function getBitsLength (length) {
    return 11 * Math.floor(length / 2) + 6 * (length % 2)
  };

  AlphanumericData.prototype.getLength = function getLength () {
    return this.data.length
  };

  AlphanumericData.prototype.getBitsLength = function getBitsLength () {
    return AlphanumericData.getBitsLength(this.data.length)
  };

  AlphanumericData.prototype.write = function write (bitBuffer) {
    var i;

    // Input data characters are divided into groups of two characters
    // and encoded as 11-bit binary codes.
    for (i = 0; i + 2 <= this.data.length; i += 2) {
      // The character value of the first character is multiplied by 45
      var value = ALPHA_NUM_CHARS.indexOf(this.data[i]) * 45;

      // The character value of the second digit is added to the product
      value += ALPHA_NUM_CHARS.indexOf(this.data[i + 1]);

      // The sum is then stored as 11-bit binary number
      bitBuffer.put(value, 11);
    }

    // If the number of input data characters is not a multiple of two,
    // the character value of the final character is encoded as a 6-bit binary number.
    if (this.data.length % 2) {
      bitBuffer.put(ALPHA_NUM_CHARS.indexOf(this.data[i]), 6);
    }
  };

  var alphanumericData = AlphanumericData;

  function ByteData (data) {
    this.mode = mode.BYTE;
    this.data = typedarrayBuffer.from(data);
  }

  ByteData.getBitsLength = function getBitsLength (length) {
    return length * 8
  };

  ByteData.prototype.getLength = function getLength () {
    return this.data.length
  };

  ByteData.prototype.getBitsLength = function getBitsLength () {
    return ByteData.getBitsLength(this.data.length)
  };

  ByteData.prototype.write = function (bitBuffer) {
    for (var i = 0, l = this.data.length; i < l; i++) {
      bitBuffer.put(this.data[i], 8);
    }
  };

  var byteData = ByteData;

  function KanjiData (data) {
    this.mode = mode.KANJI;
    this.data = data;
  }

  KanjiData.getBitsLength = function getBitsLength (length) {
    return length * 13
  };

  KanjiData.prototype.getLength = function getLength () {
    return this.data.length
  };

  KanjiData.prototype.getBitsLength = function getBitsLength () {
    return KanjiData.getBitsLength(this.data.length)
  };

  KanjiData.prototype.write = function (bitBuffer) {
    var i;

    // In the Shift JIS system, Kanji characters are represented by a two byte combination.
    // These byte values are shifted from the JIS X 0208 values.
    // JIS X 0208 gives details of the shift coded representation.
    for (i = 0; i < this.data.length; i++) {
      var value = utils.toSJIS(this.data[i]);

      // For characters with Shift JIS values from 0x8140 to 0x9FFC:
      if (value >= 0x8140 && value <= 0x9FFC) {
        // Subtract 0x8140 from Shift JIS value
        value -= 0x8140;

      // For characters with Shift JIS values from 0xE040 to 0xEBBF
      } else if (value >= 0xE040 && value <= 0xEBBF) {
        // Subtract 0xC140 from Shift JIS value
        value -= 0xC140;
      } else {
        throw new Error(
          'Invalid SJIS character: ' + this.data[i] + '\n' +
          'Make sure your charset is UTF-8')
      }

      // Multiply most significant byte of result by 0xC0
      // and add least significant byte to product
      value = (((value >>> 8) & 0xff) * 0xC0) + (value & 0xff);

      // Convert result to a 13-bit binary string
      bitBuffer.put(value, 13);
    }
  };

  var kanjiData = KanjiData;

  var dijkstra_1 = createCommonjsModule(function (module) {

  /******************************************************************************
   * Created 2008-08-19.
   *
   * Dijkstra path-finding functions. Adapted from the Dijkstar Python project.
   *
   * Copyright (C) 2008
   *   Wyatt Baldwin <self@wyattbaldwin.com>
   *   All rights reserved
   *
   * Licensed under the MIT license.
   *
   *   http://www.opensource.org/licenses/mit-license.php
   *
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   * THE SOFTWARE.
   *****************************************************************************/
  var dijkstra = {
    single_source_shortest_paths: function(graph, s, d) {
      // Predecessor map for each node that has been encountered.
      // node ID => predecessor node ID
      var predecessors = {};

      // Costs of shortest paths from s to all nodes encountered.
      // node ID => cost
      var costs = {};
      costs[s] = 0;

      // Costs of shortest paths from s to all nodes encountered; differs from
      // `costs` in that it provides easy access to the node that currently has
      // the known shortest path from s.
      // XXX: Do we actually need both `costs` and `open`?
      var open = dijkstra.PriorityQueue.make();
      open.push(s, 0);

      var closest,
          u, v,
          cost_of_s_to_u,
          adjacent_nodes,
          cost_of_e,
          cost_of_s_to_u_plus_cost_of_e,
          cost_of_s_to_v,
          first_visit;
      while (!open.empty()) {
        // In the nodes remaining in graph that have a known cost from s,
        // find the node, u, that currently has the shortest path from s.
        closest = open.pop();
        u = closest.value;
        cost_of_s_to_u = closest.cost;

        // Get nodes adjacent to u...
        adjacent_nodes = graph[u] || {};

        // ...and explore the edges that connect u to those nodes, updating
        // the cost of the shortest paths to any or all of those nodes as
        // necessary. v is the node across the current edge from u.
        for (v in adjacent_nodes) {
          if (adjacent_nodes.hasOwnProperty(v)) {
            // Get the cost of the edge running from u to v.
            cost_of_e = adjacent_nodes[v];

            // Cost of s to u plus the cost of u to v across e--this is *a*
            // cost from s to v that may or may not be less than the current
            // known cost to v.
            cost_of_s_to_u_plus_cost_of_e = cost_of_s_to_u + cost_of_e;

            // If we haven't visited v yet OR if the current known cost from s to
            // v is greater than the new cost we just found (cost of s to u plus
            // cost of u to v across e), update v's cost in the cost list and
            // update v's predecessor in the predecessor list (it's now u).
            cost_of_s_to_v = costs[v];
            first_visit = (typeof costs[v] === 'undefined');
            if (first_visit || cost_of_s_to_v > cost_of_s_to_u_plus_cost_of_e) {
              costs[v] = cost_of_s_to_u_plus_cost_of_e;
              open.push(v, cost_of_s_to_u_plus_cost_of_e);
              predecessors[v] = u;
            }
          }
        }
      }

      if (typeof d !== 'undefined' && typeof costs[d] === 'undefined') {
        var msg = ['Could not find a path from ', s, ' to ', d, '.'].join('');
        throw new Error(msg);
      }

      return predecessors;
    },

    extract_shortest_path_from_predecessor_list: function(predecessors, d) {
      var nodes = [];
      var u = d;
      var predecessor;
      while (u) {
        nodes.push(u);
        predecessor = predecessors[u];
        u = predecessors[u];
      }
      nodes.reverse();
      return nodes;
    },

    find_path: function(graph, s, d) {
      var predecessors = dijkstra.single_source_shortest_paths(graph, s, d);
      return dijkstra.extract_shortest_path_from_predecessor_list(
        predecessors, d);
    },

    /**
     * A very naive priority queue implementation.
     */
    PriorityQueue: {
      make: function (opts) {
        var T = dijkstra.PriorityQueue,
            t = {},
            key;
        opts = opts || {};
        for (key in T) {
          if (T.hasOwnProperty(key)) {
            t[key] = T[key];
          }
        }
        t.queue = [];
        t.sorter = opts.sorter || T.default_sorter;
        return t;
      },

      default_sorter: function (a, b) {
        return a.cost - b.cost;
      },

      /**
       * Add a new item to the queue and ensure the highest priority element
       * is at the front of the queue.
       */
      push: function (value, cost) {
        var item = {value: value, cost: cost};
        this.queue.push(item);
        this.queue.sort(this.sorter);
      },

      /**
       * Return the highest priority element in the queue.
       */
      pop: function () {
        return this.queue.shift();
      },

      empty: function () {
        return this.queue.length === 0;
      }
    }
  };


  // node.js module exports
  {
    module.exports = dijkstra;
  }
  });

  var segments = createCommonjsModule(function (module, exports) {
  /**
   * Returns UTF8 byte length
   *
   * @param  {String} str Input string
   * @return {Number}     Number of byte
   */
  function getStringByteLength (str) {
    return unescape(encodeURIComponent(str)).length
  }

  /**
   * Get a list of segments of the specified mode
   * from a string
   *
   * @param  {Mode}   mode Segment mode
   * @param  {String} str  String to process
   * @return {Array}       Array of object with segments data
   */
  function getSegments (regex, mode, str) {
    var segments = [];
    var result;

    while ((result = regex.exec(str)) !== null) {
      segments.push({
        data: result[0],
        index: result.index,
        mode: mode,
        length: result[0].length
      });
    }

    return segments
  }

  /**
   * Extracts a series of segments with the appropriate
   * modes from a string
   *
   * @param  {String} dataStr Input string
   * @return {Array}          Array of object with segments data
   */
  function getSegmentsFromString (dataStr) {
    var numSegs = getSegments(regex.NUMERIC, mode.NUMERIC, dataStr);
    var alphaNumSegs = getSegments(regex.ALPHANUMERIC, mode.ALPHANUMERIC, dataStr);
    var byteSegs;
    var kanjiSegs;

    if (utils.isKanjiModeEnabled()) {
      byteSegs = getSegments(regex.BYTE, mode.BYTE, dataStr);
      kanjiSegs = getSegments(regex.KANJI, mode.KANJI, dataStr);
    } else {
      byteSegs = getSegments(regex.BYTE_KANJI, mode.BYTE, dataStr);
      kanjiSegs = [];
    }

    var segs = numSegs.concat(alphaNumSegs, byteSegs, kanjiSegs);

    return segs
      .sort(function (s1, s2) {
        return s1.index - s2.index
      })
      .map(function (obj) {
        return {
          data: obj.data,
          mode: obj.mode,
          length: obj.length
        }
      })
  }

  /**
   * Returns how many bits are needed to encode a string of
   * specified length with the specified mode
   *
   * @param  {Number} length String length
   * @param  {Mode} mode     Segment mode
   * @return {Number}        Bit length
   */
  function getSegmentBitsLength (length, mode$1) {
    switch (mode$1) {
      case mode.NUMERIC:
        return numericData.getBitsLength(length)
      case mode.ALPHANUMERIC:
        return alphanumericData.getBitsLength(length)
      case mode.KANJI:
        return kanjiData.getBitsLength(length)
      case mode.BYTE:
        return byteData.getBitsLength(length)
    }
  }

  /**
   * Merges adjacent segments which have the same mode
   *
   * @param  {Array} segs Array of object with segments data
   * @return {Array}      Array of object with segments data
   */
  function mergeSegments (segs) {
    return segs.reduce(function (acc, curr) {
      var prevSeg = acc.length - 1 >= 0 ? acc[acc.length - 1] : null;
      if (prevSeg && prevSeg.mode === curr.mode) {
        acc[acc.length - 1].data += curr.data;
        return acc
      }

      acc.push(curr);
      return acc
    }, [])
  }

  /**
   * Generates a list of all possible nodes combination which
   * will be used to build a segments graph.
   *
   * Nodes are divided by groups. Each group will contain a list of all the modes
   * in which is possible to encode the given text.
   *
   * For example the text '12345' can be encoded as Numeric, Alphanumeric or Byte.
   * The group for '12345' will contain then 3 objects, one for each
   * possible encoding mode.
   *
   * Each node represents a possible segment.
   *
   * @param  {Array} segs Array of object with segments data
   * @return {Array}      Array of object with segments data
   */
  function buildNodes (segs) {
    var nodes = [];
    for (var i = 0; i < segs.length; i++) {
      var seg = segs[i];

      switch (seg.mode) {
        case mode.NUMERIC:
          nodes.push([seg,
            { data: seg.data, mode: mode.ALPHANUMERIC, length: seg.length },
            { data: seg.data, mode: mode.BYTE, length: seg.length }
          ]);
          break
        case mode.ALPHANUMERIC:
          nodes.push([seg,
            { data: seg.data, mode: mode.BYTE, length: seg.length }
          ]);
          break
        case mode.KANJI:
          nodes.push([seg,
            { data: seg.data, mode: mode.BYTE, length: getStringByteLength(seg.data) }
          ]);
          break
        case mode.BYTE:
          nodes.push([
            { data: seg.data, mode: mode.BYTE, length: getStringByteLength(seg.data) }
          ]);
      }
    }

    return nodes
  }

  /**
   * Builds a graph from a list of nodes.
   * All segments in each node group will be connected with all the segments of
   * the next group and so on.
   *
   * At each connection will be assigned a weight depending on the
   * segment's byte length.
   *
   * @param  {Array} nodes    Array of object with segments data
   * @param  {Number} version QR Code version
   * @return {Object}         Graph of all possible segments
   */
  function buildGraph (nodes, version) {
    var table = {};
    var graph = {'start': {}};
    var prevNodeIds = ['start'];

    for (var i = 0; i < nodes.length; i++) {
      var nodeGroup = nodes[i];
      var currentNodeIds = [];

      for (var j = 0; j < nodeGroup.length; j++) {
        var node = nodeGroup[j];
        var key = '' + i + j;

        currentNodeIds.push(key);
        table[key] = { node: node, lastCount: 0 };
        graph[key] = {};

        for (var n = 0; n < prevNodeIds.length; n++) {
          var prevNodeId = prevNodeIds[n];

          if (table[prevNodeId] && table[prevNodeId].node.mode === node.mode) {
            graph[prevNodeId][key] =
              getSegmentBitsLength(table[prevNodeId].lastCount + node.length, node.mode) -
              getSegmentBitsLength(table[prevNodeId].lastCount, node.mode);

            table[prevNodeId].lastCount += node.length;
          } else {
            if (table[prevNodeId]) table[prevNodeId].lastCount = node.length;

            graph[prevNodeId][key] = getSegmentBitsLength(node.length, node.mode) +
              4 + mode.getCharCountIndicator(node.mode, version); // switch cost
          }
        }
      }

      prevNodeIds = currentNodeIds;
    }

    for (n = 0; n < prevNodeIds.length; n++) {
      graph[prevNodeIds[n]]['end'] = 0;
    }

    return { map: graph, table: table }
  }

  /**
   * Builds a segment from a specified data and mode.
   * If a mode is not specified, the more suitable will be used.
   *
   * @param  {String} data             Input data
   * @param  {Mode | String} modesHint Data mode
   * @return {Segment}                 Segment
   */
  function buildSingleSegment (data, modesHint) {
    var mode$1;
    var bestMode = mode.getBestModeForData(data);

    mode$1 = mode.from(modesHint, bestMode);

    // Make sure data can be encoded
    if (mode$1 !== mode.BYTE && mode$1.bit < bestMode.bit) {
      throw new Error('"' + data + '"' +
        ' cannot be encoded with mode ' + mode.toString(mode$1) +
        '.\n Suggested mode is: ' + mode.toString(bestMode))
    }

    // Use Mode.BYTE if Kanji support is disabled
    if (mode$1 === mode.KANJI && !utils.isKanjiModeEnabled()) {
      mode$1 = mode.BYTE;
    }

    switch (mode$1) {
      case mode.NUMERIC:
        return new numericData(data)

      case mode.ALPHANUMERIC:
        return new alphanumericData(data)

      case mode.KANJI:
        return new kanjiData(data)

      case mode.BYTE:
        return new byteData(data)
    }
  }

  /**
   * Builds a list of segments from an array.
   * Array can contain Strings or Objects with segment's info.
   *
   * For each item which is a string, will be generated a segment with the given
   * string and the more appropriate encoding mode.
   *
   * For each item which is an object, will be generated a segment with the given
   * data and mode.
   * Objects must contain at least the property "data".
   * If property "mode" is not present, the more suitable mode will be used.
   *
   * @param  {Array} array Array of objects with segments data
   * @return {Array}       Array of Segments
   */
  exports.fromArray = function fromArray (array) {
    return array.reduce(function (acc, seg) {
      if (typeof seg === 'string') {
        acc.push(buildSingleSegment(seg, null));
      } else if (seg.data) {
        acc.push(buildSingleSegment(seg.data, seg.mode));
      }

      return acc
    }, [])
  };

  /**
   * Builds an optimized sequence of segments from a string,
   * which will produce the shortest possible bitstream.
   *
   * @param  {String} data    Input string
   * @param  {Number} version QR Code version
   * @return {Array}          Array of segments
   */
  exports.fromString = function fromString (data, version) {
    var segs = getSegmentsFromString(data, utils.isKanjiModeEnabled());

    var nodes = buildNodes(segs);
    var graph = buildGraph(nodes, version);
    var path = dijkstra_1.find_path(graph.map, 'start', 'end');

    var optimizedSegs = [];
    for (var i = 1; i < path.length - 1; i++) {
      optimizedSegs.push(graph.table[path[i]].node);
    }

    return exports.fromArray(mergeSegments(optimizedSegs))
  };

  /**
   * Splits a string in various segments with the modes which
   * best represent their content.
   * The produced segments are far from being optimized.
   * The output of this function is only used to estimate a QR Code version
   * which may contain the data.
   *
   * @param  {string} data Input string
   * @return {Array}       Array of segments
   */
  exports.rawSplit = function rawSplit (data) {
    return exports.fromArray(
      getSegmentsFromString(data, utils.isKanjiModeEnabled())
    )
  };
  });
  var segments_1 = segments.fromArray;
  var segments_2 = segments.fromString;
  var segments_3 = segments.rawSplit;

  /**
   * QRCode for JavaScript
   *
   * modified by Ryan Day for nodejs support
   * Copyright (c) 2011 Ryan Day
   *
   * Licensed under the MIT license:
   *   http://www.opensource.org/licenses/mit-license.php
   *
  //---------------------------------------------------------------------
  // QRCode for JavaScript
  //
  // Copyright (c) 2009 Kazuhiko Arase
  //
  // URL: http://www.d-project.com/
  //
  // Licensed under the MIT license:
  //   http://www.opensource.org/licenses/mit-license.php
  //
  // The word "QR Code" is registered trademark of
  // DENSO WAVE INCORPORATED
  //   http://www.denso-wave.com/qrcode/faqpatent-e.html
  //
  //---------------------------------------------------------------------
  */

  /**
   * Add finder patterns bits to matrix
   *
   * @param  {BitMatrix} matrix  Modules matrix
   * @param  {Number}    version QR Code version
   */
  function setupFinderPattern (matrix, version) {
    var size = matrix.size;
    var pos = finderPattern.getPositions(version);

    for (var i = 0; i < pos.length; i++) {
      var row = pos[i][0];
      var col = pos[i][1];

      for (var r = -1; r <= 7; r++) {
        if (row + r <= -1 || size <= row + r) continue

        for (var c = -1; c <= 7; c++) {
          if (col + c <= -1 || size <= col + c) continue

          if ((r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
            (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
            matrix.set(row + r, col + c, true, true);
          } else {
            matrix.set(row + r, col + c, false, true);
          }
        }
      }
    }
  }

  /**
   * Add timing pattern bits to matrix
   *
   * Note: this function must be called before {@link setupAlignmentPattern}
   *
   * @param  {BitMatrix} matrix Modules matrix
   */
  function setupTimingPattern (matrix) {
    var size = matrix.size;

    for (var r = 8; r < size - 8; r++) {
      var value = r % 2 === 0;
      matrix.set(r, 6, value, true);
      matrix.set(6, r, value, true);
    }
  }

  /**
   * Add alignment patterns bits to matrix
   *
   * Note: this function must be called after {@link setupTimingPattern}
   *
   * @param  {BitMatrix} matrix  Modules matrix
   * @param  {Number}    version QR Code version
   */
  function setupAlignmentPattern (matrix, version) {
    var pos = alignmentPattern.getPositions(version);

    for (var i = 0; i < pos.length; i++) {
      var row = pos[i][0];
      var col = pos[i][1];

      for (var r = -2; r <= 2; r++) {
        for (var c = -2; c <= 2; c++) {
          if (r === -2 || r === 2 || c === -2 || c === 2 ||
            (r === 0 && c === 0)) {
            matrix.set(row + r, col + c, true, true);
          } else {
            matrix.set(row + r, col + c, false, true);
          }
        }
      }
    }
  }

  /**
   * Add version info bits to matrix
   *
   * @param  {BitMatrix} matrix  Modules matrix
   * @param  {Number}    version QR Code version
   */
  function setupVersionInfo (matrix, version$1) {
    var size = matrix.size;
    var bits = version.getEncodedBits(version$1);
    var row, col, mod;

    for (var i = 0; i < 18; i++) {
      row = Math.floor(i / 3);
      col = i % 3 + size - 8 - 3;
      mod = ((bits >> i) & 1) === 1;

      matrix.set(row, col, mod, true);
      matrix.set(col, row, mod, true);
    }
  }

  /**
   * Add format info bits to matrix
   *
   * @param  {BitMatrix} matrix               Modules matrix
   * @param  {ErrorCorrectionLevel}    errorCorrectionLevel Error correction level
   * @param  {Number}    maskPattern          Mask pattern reference value
   */
  function setupFormatInfo (matrix, errorCorrectionLevel, maskPattern) {
    var size = matrix.size;
    var bits = formatInfo.getEncodedBits(errorCorrectionLevel, maskPattern);
    var i, mod;

    for (i = 0; i < 15; i++) {
      mod = ((bits >> i) & 1) === 1;

      // vertical
      if (i < 6) {
        matrix.set(i, 8, mod, true);
      } else if (i < 8) {
        matrix.set(i + 1, 8, mod, true);
      } else {
        matrix.set(size - 15 + i, 8, mod, true);
      }

      // horizontal
      if (i < 8) {
        matrix.set(8, size - i - 1, mod, true);
      } else if (i < 9) {
        matrix.set(8, 15 - i - 1 + 1, mod, true);
      } else {
        matrix.set(8, 15 - i - 1, mod, true);
      }
    }

    // fixed module
    matrix.set(size - 8, 8, 1, true);
  }

  /**
   * Add encoded data bits to matrix
   *
   * @param  {BitMatrix} matrix Modules matrix
   * @param  {Buffer}    data   Data codewords
   */
  function setupData (matrix, data) {
    var size = matrix.size;
    var inc = -1;
    var row = size - 1;
    var bitIndex = 7;
    var byteIndex = 0;

    for (var col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;

      while (true) {
        for (var c = 0; c < 2; c++) {
          if (!matrix.isReserved(row, col - c)) {
            var dark = false;

            if (byteIndex < data.length) {
              dark = (((data[byteIndex] >>> bitIndex) & 1) === 1);
            }

            matrix.set(row, col - c, dark);
            bitIndex--;

            if (bitIndex === -1) {
              byteIndex++;
              bitIndex = 7;
            }
          }
        }

        row += inc;

        if (row < 0 || size <= row) {
          row -= inc;
          inc = -inc;
          break
        }
      }
    }
  }

  /**
   * Create encoded codewords from data input
   *
   * @param  {Number}   version              QR Code version
   * @param  {ErrorCorrectionLevel}   errorCorrectionLevel Error correction level
   * @param  {ByteData} data                 Data input
   * @return {Buffer}                        Buffer containing encoded codewords
   */
  function createData (version, errorCorrectionLevel, segments) {
    // Prepare data buffer
    var buffer = new bitBuffer();

    segments.forEach(function (data) {
      // prefix data with mode indicator (4 bits)
      buffer.put(data.mode.bit, 4);

      // Prefix data with character count indicator.
      // The character count indicator is a string of bits that represents the
      // number of characters that are being encoded.
      // The character count indicator must be placed after the mode indicator
      // and must be a certain number of bits long, depending on the QR version
      // and data mode
      // @see {@link Mode.getCharCountIndicator}.
      buffer.put(data.getLength(), mode.getCharCountIndicator(data.mode, version));

      // add binary data sequence to buffer
      data.write(buffer);
    });

    // Calculate required number of bits
    var totalCodewords = utils.getSymbolTotalCodewords(version);
    var ecTotalCodewords = errorCorrectionCode.getTotalCodewordsCount(version, errorCorrectionLevel);
    var dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;

    // Add a terminator.
    // If the bit string is shorter than the total number of required bits,
    // a terminator of up to four 0s must be added to the right side of the string.
    // If the bit string is more than four bits shorter than the required number of bits,
    // add four 0s to the end.
    if (buffer.getLengthInBits() + 4 <= dataTotalCodewordsBits) {
      buffer.put(0, 4);
    }

    // If the bit string is fewer than four bits shorter, add only the number of 0s that
    // are needed to reach the required number of bits.

    // After adding the terminator, if the number of bits in the string is not a multiple of 8,
    // pad the string on the right with 0s to make the string's length a multiple of 8.
    while (buffer.getLengthInBits() % 8 !== 0) {
      buffer.putBit(0);
    }

    // Add pad bytes if the string is still shorter than the total number of required bits.
    // Extend the buffer to fill the data capacity of the symbol corresponding to
    // the Version and Error Correction Level by adding the Pad Codewords 11101100 (0xEC)
    // and 00010001 (0x11) alternately.
    var remainingByte = (dataTotalCodewordsBits - buffer.getLengthInBits()) / 8;
    for (var i = 0; i < remainingByte; i++) {
      buffer.put(i % 2 ? 0x11 : 0xEC, 8);
    }

    return createCodewords(buffer, version, errorCorrectionLevel)
  }

  /**
   * Encode input data with Reed-Solomon and return codewords with
   * relative error correction bits
   *
   * @param  {BitBuffer} bitBuffer            Data to encode
   * @param  {Number}    version              QR Code version
   * @param  {ErrorCorrectionLevel} errorCorrectionLevel Error correction level
   * @return {Buffer}                         Buffer containing encoded codewords
   */
  function createCodewords (bitBuffer, version, errorCorrectionLevel) {
    // Total codewords for this QR code version (Data + Error correction)
    var totalCodewords = utils.getSymbolTotalCodewords(version);

    // Total number of error correction codewords
    var ecTotalCodewords = errorCorrectionCode.getTotalCodewordsCount(version, errorCorrectionLevel);

    // Total number of data codewords
    var dataTotalCodewords = totalCodewords - ecTotalCodewords;

    // Total number of blocks
    var ecTotalBlocks = errorCorrectionCode.getBlocksCount(version, errorCorrectionLevel);

    // Calculate how many blocks each group should contain
    var blocksInGroup2 = totalCodewords % ecTotalBlocks;
    var blocksInGroup1 = ecTotalBlocks - blocksInGroup2;

    var totalCodewordsInGroup1 = Math.floor(totalCodewords / ecTotalBlocks);

    var dataCodewordsInGroup1 = Math.floor(dataTotalCodewords / ecTotalBlocks);
    var dataCodewordsInGroup2 = dataCodewordsInGroup1 + 1;

    // Number of EC codewords is the same for both groups
    var ecCount = totalCodewordsInGroup1 - dataCodewordsInGroup1;

    // Initialize a Reed-Solomon encoder with a generator polynomial of degree ecCount
    var rs = new reedSolomonEncoder(ecCount);

    var offset = 0;
    var dcData = new Array(ecTotalBlocks);
    var ecData = new Array(ecTotalBlocks);
    var maxDataSize = 0;
    var buffer = typedarrayBuffer.from(bitBuffer.buffer);

    // Divide the buffer into the required number of blocks
    for (var b = 0; b < ecTotalBlocks; b++) {
      var dataSize = b < blocksInGroup1 ? dataCodewordsInGroup1 : dataCodewordsInGroup2;

      // extract a block of data from buffer
      dcData[b] = buffer.slice(offset, offset + dataSize);

      // Calculate EC codewords for this data block
      ecData[b] = rs.encode(dcData[b]);

      offset += dataSize;
      maxDataSize = Math.max(maxDataSize, dataSize);
    }

    // Create final data
    // Interleave the data and error correction codewords from each block
    var data = typedarrayBuffer.alloc(totalCodewords);
    var index = 0;
    var i, r;

    // Add data codewords
    for (i = 0; i < maxDataSize; i++) {
      for (r = 0; r < ecTotalBlocks; r++) {
        if (i < dcData[r].length) {
          data[index++] = dcData[r][i];
        }
      }
    }

    // Apped EC codewords
    for (i = 0; i < ecCount; i++) {
      for (r = 0; r < ecTotalBlocks; r++) {
        data[index++] = ecData[r][i];
      }
    }

    return data
  }

  /**
   * Build QR Code symbol
   *
   * @param  {String} data                 Input string
   * @param  {Number} version              QR Code version
   * @param  {ErrorCorretionLevel} errorCorrectionLevel Error level
   * @param  {MaskPattern} maskPattern     Mask pattern
   * @return {Object}                      Object containing symbol data
   */
  function createSymbol (data, version$1, errorCorrectionLevel, maskPattern$1) {
    var segments$1;

    if (isarray(data)) {
      segments$1 = segments.fromArray(data);
    } else if (typeof data === 'string') {
      var estimatedVersion = version$1;

      if (!estimatedVersion) {
        var rawSegments = segments.rawSplit(data);

        // Estimate best version that can contain raw splitted segments
        estimatedVersion = version.getBestVersionForData(rawSegments,
          errorCorrectionLevel);
      }

      // Build optimized segments
      // If estimated version is undefined, try with the highest version
      segments$1 = segments.fromString(data, estimatedVersion || 40);
    } else {
      throw new Error('Invalid data')
    }

    // Get the min version that can contain data
    var bestVersion = version.getBestVersionForData(segments$1,
        errorCorrectionLevel);

    // If no version is found, data cannot be stored
    if (!bestVersion) {
      throw new Error('The amount of data is too big to be stored in a QR Code')
    }

    // If not specified, use min version as default
    if (!version$1) {
      version$1 = bestVersion;

    // Check if the specified version can contain the data
    } else if (version$1 < bestVersion) {
      throw new Error('\n' +
        'The chosen QR Code version cannot contain this amount of data.\n' +
        'Minimum version required to store current data is: ' + bestVersion + '.\n'
      )
    }

    var dataBits = createData(version$1, errorCorrectionLevel, segments$1);

    // Allocate matrix buffer
    var moduleCount = utils.getSymbolSize(version$1);
    var modules = new bitMatrix(moduleCount);

    // Add function modules
    setupFinderPattern(modules, version$1);
    setupTimingPattern(modules);
    setupAlignmentPattern(modules, version$1);

    // Add temporary dummy bits for format info just to set them as reserved.
    // This is needed to prevent these bits from being masked by {@link MaskPattern.applyMask}
    // since the masking operation must be performed only on the encoding region.
    // These blocks will be replaced with correct values later in code.
    setupFormatInfo(modules, errorCorrectionLevel, 0);

    if (version$1 >= 7) {
      setupVersionInfo(modules, version$1);
    }

    // Add data codewords
    setupData(modules, dataBits);

    if (isNaN(maskPattern$1)) {
      // Find best mask pattern
      maskPattern$1 = maskPattern.getBestMask(modules,
        setupFormatInfo.bind(null, modules, errorCorrectionLevel));
    }

    // Apply mask pattern
    maskPattern.applyMask(maskPattern$1, modules);

    // Replace format info bits with correct values
    setupFormatInfo(modules, errorCorrectionLevel, maskPattern$1);

    return {
      modules: modules,
      version: version$1,
      errorCorrectionLevel: errorCorrectionLevel,
      maskPattern: maskPattern$1,
      segments: segments$1
    }
  }

  /**
   * QR Code
   *
   * @param {String | Array} data                 Input data
   * @param {Object} options                      Optional configurations
   * @param {Number} options.version              QR Code version
   * @param {String} options.errorCorrectionLevel Error correction level
   * @param {Function} options.toSJISFunc         Helper func to convert utf8 to sjis
   */
  var create = function create (data, options) {
    if (typeof data === 'undefined' || data === '') {
      throw new Error('No input text')
    }

    var errorCorrectionLevel$1 = errorCorrectionLevel.M;
    var version$1;
    var mask;

    if (typeof options !== 'undefined') {
      // Use higher error correction level as default
      errorCorrectionLevel$1 = errorCorrectionLevel.from(options.errorCorrectionLevel, errorCorrectionLevel.M);
      version$1 = version.from(options.version);
      mask = maskPattern.from(options.maskPattern);

      if (options.toSJISFunc) {
        utils.setToSJISFunction(options.toSJISFunc);
      }
    }

    return createSymbol(data, version$1, errorCorrectionLevel$1, mask)
  };

  var qrcode = {
  	create: create
  };

  var utils$1 = createCommonjsModule(function (module, exports) {
  function hex2rgba (hex) {
    if (typeof hex === 'number') {
      hex = hex.toString();
    }

    if (typeof hex !== 'string') {
      throw new Error('Color should be defined as hex string')
    }

    var hexCode = hex.slice().replace('#', '').split('');
    if (hexCode.length < 3 || hexCode.length === 5 || hexCode.length > 8) {
      throw new Error('Invalid hex color: ' + hex)
    }

    // Convert from short to long form (fff -> ffffff)
    if (hexCode.length === 3 || hexCode.length === 4) {
      hexCode = Array.prototype.concat.apply([], hexCode.map(function (c) {
        return [c, c]
      }));
    }

    // Add default alpha value
    if (hexCode.length === 6) hexCode.push('F', 'F');

    var hexValue = parseInt(hexCode.join(''), 16);

    return {
      r: (hexValue >> 24) & 255,
      g: (hexValue >> 16) & 255,
      b: (hexValue >> 8) & 255,
      a: hexValue & 255,
      hex: '#' + hexCode.slice(0, 6).join('')
    }
  }

  exports.getOptions = function getOptions (options) {
    if (!options) options = {};
    if (!options.color) options.color = {};

    var margin = typeof options.margin === 'undefined' ||
      options.margin === null ||
      options.margin < 0 ? 4 : options.margin;

    var width = options.width && options.width >= 21 ? options.width : undefined;
    var scale = options.scale || 4;

    return {
      width: width,
      scale: width ? 4 : scale,
      margin: margin,
      color: {
        dark: hex2rgba(options.color.dark || '#000000ff'),
        light: hex2rgba(options.color.light || '#ffffffff')
      },
      type: options.type,
      rendererOpts: options.rendererOpts || {}
    }
  };

  exports.getScale = function getScale (qrSize, opts) {
    return opts.width && opts.width >= qrSize + opts.margin * 2
      ? opts.width / (qrSize + opts.margin * 2)
      : opts.scale
  };

  exports.getImageWidth = function getImageWidth (qrSize, opts) {
    var scale = exports.getScale(qrSize, opts);
    return Math.floor((qrSize + opts.margin * 2) * scale)
  };

  exports.qrToImageData = function qrToImageData (imgData, qr, opts) {
    var size = qr.modules.size;
    var data = qr.modules.data;
    var scale = exports.getScale(size, opts);
    var symbolSize = Math.floor((size + opts.margin * 2) * scale);
    var scaledMargin = opts.margin * scale;
    var palette = [opts.color.light, opts.color.dark];

    for (var i = 0; i < symbolSize; i++) {
      for (var j = 0; j < symbolSize; j++) {
        var posDst = (i * symbolSize + j) * 4;
        var pxColor = opts.color.light;

        if (i >= scaledMargin && j >= scaledMargin &&
          i < symbolSize - scaledMargin && j < symbolSize - scaledMargin) {
          var iSrc = Math.floor((i - scaledMargin) / scale);
          var jSrc = Math.floor((j - scaledMargin) / scale);
          pxColor = palette[data[iSrc * size + jSrc] ? 1 : 0];
        }

        imgData[posDst++] = pxColor.r;
        imgData[posDst++] = pxColor.g;
        imgData[posDst++] = pxColor.b;
        imgData[posDst] = pxColor.a;
      }
    }
  };
  });
  var utils_1 = utils$1.getOptions;
  var utils_2 = utils$1.getScale;
  var utils_3 = utils$1.getImageWidth;
  var utils_4 = utils$1.qrToImageData;

  var canvas = createCommonjsModule(function (module, exports) {
  function clearCanvas (ctx, canvas, size) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (!canvas.style) canvas.style = {};
    canvas.height = size;
    canvas.width = size;
    canvas.style.height = size + 'px';
    canvas.style.width = size + 'px';
  }

  function getCanvasElement () {
    try {
      return document.createElement('canvas')
    } catch (e) {
      throw new Error('You need to specify a canvas element')
    }
  }

  exports.render = function render (qrData, canvas, options) {
    var opts = options;
    var canvasEl = canvas;

    if (typeof opts === 'undefined' && (!canvas || !canvas.getContext)) {
      opts = canvas;
      canvas = undefined;
    }

    if (!canvas) {
      canvasEl = getCanvasElement();
    }

    opts = utils$1.getOptions(opts);
    var size = utils$1.getImageWidth(qrData.modules.size, opts);

    var ctx = canvasEl.getContext('2d');
    var image = ctx.createImageData(size, size);
    utils$1.qrToImageData(image.data, qrData, opts);

    clearCanvas(ctx, canvasEl, size);
    ctx.putImageData(image, 0, 0);

    return canvasEl
  };

  exports.renderToDataURL = function renderToDataURL (qrData, canvas, options) {
    var opts = options;

    if (typeof opts === 'undefined' && (!canvas || !canvas.getContext)) {
      opts = canvas;
      canvas = undefined;
    }

    if (!opts) opts = {};

    var canvasEl = exports.render(qrData, canvas, opts);

    var type = opts.type || 'image/png';
    var rendererOpts = opts.rendererOpts || {};

    return canvasEl.toDataURL(type, rendererOpts.quality)
  };
  });
  var canvas_1 = canvas.render;
  var canvas_2 = canvas.renderToDataURL;

  function getColorAttrib (color, attrib) {
    var alpha = color.a / 255;
    var str = attrib + '="' + color.hex + '"';

    return alpha < 1
      ? str + ' ' + attrib + '-opacity="' + alpha.toFixed(2).slice(1) + '"'
      : str
  }

  function svgCmd (cmd, x, y) {
    var str = cmd + x;
    if (typeof y !== 'undefined') str += ' ' + y;

    return str
  }

  function qrToPath (data, size, margin) {
    var path = '';
    var moveBy = 0;
    var newRow = false;
    var lineLength = 0;

    for (var i = 0; i < data.length; i++) {
      var col = Math.floor(i % size);
      var row = Math.floor(i / size);

      if (!col && !newRow) newRow = true;

      if (data[i]) {
        lineLength++;

        if (!(i > 0 && col > 0 && data[i - 1])) {
          path += newRow
            ? svgCmd('M', col + margin, 0.5 + row + margin)
            : svgCmd('m', moveBy, 0);

          moveBy = 0;
          newRow = false;
        }

        if (!(col + 1 < size && data[i + 1])) {
          path += svgCmd('h', lineLength);
          lineLength = 0;
        }
      } else {
        moveBy++;
      }
    }

    return path
  }

  var render = function render (qrData, options, cb) {
    var opts = utils$1.getOptions(options);
    var size = qrData.modules.size;
    var data = qrData.modules.data;
    var qrcodesize = size + opts.margin * 2;

    var bg = !opts.color.light.a
      ? ''
      : '<path ' + getColorAttrib(opts.color.light, 'fill') +
        ' d="M0 0h' + qrcodesize + 'v' + qrcodesize + 'H0z"/>';

    var path =
      '<path ' + getColorAttrib(opts.color.dark, 'stroke') +
      ' d="' + qrToPath(data, size, opts.margin) + '"/>';

    var viewBox = 'viewBox="' + '0 0 ' + qrcodesize + ' ' + qrcodesize + '"';

    var width = !opts.width ? '' : 'width="' + opts.width + '" height="' + opts.width + '" ';

    var svgTag = '<svg xmlns="http://www.w3.org/2000/svg" ' + width + viewBox + ' shape-rendering="crispEdges">' + bg + path + '</svg>\n';

    if (typeof cb === 'function') {
      cb(null, svgTag);
    }

    return svgTag
  };

  var svgTag = {
  	render: render
  };

  function renderCanvas (renderFunc, canvas, text, opts, cb) {
    var args = [].slice.call(arguments, 1);
    var argsNum = args.length;
    var isLastArgCb = typeof args[argsNum - 1] === 'function';

    if (!isLastArgCb && !canPromise()) {
      throw new Error('Callback required as last argument')
    }

    if (isLastArgCb) {
      if (argsNum < 2) {
        throw new Error('Too few arguments provided')
      }

      if (argsNum === 2) {
        cb = text;
        text = canvas;
        canvas = opts = undefined;
      } else if (argsNum === 3) {
        if (canvas.getContext && typeof cb === 'undefined') {
          cb = opts;
          opts = undefined;
        } else {
          cb = opts;
          opts = text;
          text = canvas;
          canvas = undefined;
        }
      }
    } else {
      if (argsNum < 1) {
        throw new Error('Too few arguments provided')
      }

      if (argsNum === 1) {
        text = canvas;
        canvas = opts = undefined;
      } else if (argsNum === 2 && !canvas.getContext) {
        opts = text;
        text = canvas;
        canvas = undefined;
      }

      return new Promise(function (resolve, reject) {
        try {
          var data = qrcode.create(text, opts);
          resolve(renderFunc(data, canvas, opts));
        } catch (e) {
          reject(e);
        }
      })
    }

    try {
      var data = qrcode.create(text, opts);
      cb(null, renderFunc(data, canvas, opts));
    } catch (e) {
      cb(e);
    }
  }

  var create$1 = qrcode.create;
  var toCanvas = renderCanvas.bind(null, canvas.render);
  var toDataURL = renderCanvas.bind(null, canvas.renderToDataURL);

  // only svg for now.
  var toString_1 = renderCanvas.bind(null, function (data, _, opts) {
    return svgTag.render(data, opts)
  });

  var browser = {
  	create: create$1,
  	toCanvas: toCanvas,
  	toDataURL: toDataURL,
  	toString: toString_1
  };

  var isMobile = function isMobile() {
    return navigator && ('userAgent' in navigator && navigator.userAgent.match(/iPhone|iPod|iPad|Android/i) || navigator.maxTouchPoints > 1) && !window.MSStream;
  };

  var removeLoader = function removeLoader(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  };

  var haveStyleSheet = false;

  var setLoader = function setLoader(element, styles) {
    var loaderClass = "".concat(styles.prefix || 'wwp_', "qrcode_loader");
    var loader = document.createElement('div');
    loader.className = loaderClass;
    loader.innerHTML = "<div class=\"".concat(loaderClass, "_blk\"></div>\n  <div class=\"").concat(loaderClass, "_blk ").concat(loaderClass, "_delay\"></div>\n  <div class=\"").concat(loaderClass, "_blk ").concat(loaderClass, "_delay\"></div>\n  <div class=\"").concat(loaderClass, "_blk\"></div>");

    if (!haveStyleSheet) {
      var style = document.createElement('style');
      style.innerHTML = "@keyframes ".concat(styles.prefix || 'wwp_', "pulse {\n      0%   { opacity: 1; }\n      100% { opacity: 0; }\n    }\n    .").concat(loaderClass, " {\n      display: flex;\n      flex-direction: row;\n      flex-wrap: wrap;\n      justify-content: space-around;\n      align-items: center;\n      width: 30%;\n      height: 30%;\n      margin-left: 35%;\n      margin-top: 35%;\n    }\n    .").concat(loaderClass, "_blk {\n      height: 35%;\n      width: 35%;\n      animation: ").concat(styles.prefix || 'wwp_', "pulse 0.75s ease-in infinite alternate;\n      background-color: #cccccc;\n    }\n    .").concat(loaderClass, "_delay {\n      animation-delay: 0.75s;\n    }");
      document.getElementsByTagName('head')[0].appendChild(style);
      haveStyleSheet = true;
    }

    removeLoader(element);
    element.appendChild(loader);
  };

  var setRefersh = function setRefersh(element, error) {
    var httpsRequired = error instanceof WWPassError && error.code === WWPASS_STATUS.SSL_REQUIRED;
    var offline = window.navigator.onLine !== undefined && !window.navigator.onLine;
    var wrapper = document.createElement('div');
    wrapper.style.display = 'flex';
    wrapper.style.alignItems = 'center';
    wrapper.style.height = '100%';
    wrapper.style.width = '100%';
    var refreshNote = document.createElement('div');
    refreshNote.style.margin = '0 10%';
    refreshNote.style.width = '80%';
    refreshNote.style.textAlign = 'center';
    refreshNote.style.overflow = 'hidden';
    var text = 'Error occured';

    if (httpsRequired) {
      text = 'Please use HTTPS';
    } else if (offline) {
      text = 'No internet connection';
    }

    refreshNote.innerHTML = "<p style=\"margin:0; font-size: 1.2em; color: black;\">".concat(text, "</p>");
    var refreshButton = null;

    if (!httpsRequired) {
      refreshButton = document.createElement('a');
      refreshButton.textContent = 'Retry';
      refreshButton.style.fontWeight = '400';
      refreshButton.style.fontFamily = '"Arial", sans-serif';
      refreshButton.style.fontSize = '1.2em';
      refreshButton.style.lineHeight = '1.7em';
      refreshButton.style.cursor = 'pointer';
      refreshButton.href = '#';
      refreshNote.appendChild(refreshButton);
    }

    wrapper.appendChild(refreshNote); // eslint-disable-next-line no-console

    console.error("Error in WWPass Library: ".concat(error));
    removeLoader(element);
    element.appendChild(wrapper);
    return httpsRequired ? Promise.reject(error.message) : new Promise(function (resolve) {
      // Refresh after 1 minute or on click
      setTimeout(function () {
        resolve({
          refresh: true
        });
      }, 60000);
      refreshButton.addEventListener('click', function (event) {
        resolve({
          refresh: true
        });
        event.preventDefault();
      });

      if (offline) {
        window.addEventListener('online', function () {
          return resolve({
            refresh: true
          });
        });
      }
    });
  };

  var debouncePageVisibilityFactory = function debouncePageVisibilityFactory() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'visible';
    var debounce = null;
    return function (fn) {
      debounce = fn;

      var onDebounce = function onDebounce() {
        if (document.visibilityState === state) {
          debounce();
          document.removeEventListener('visibilitychange', onDebounce);
        }
      };

      if (document.visibilityState === state) {
        debounce();
      } else {
        document.addEventListener('visibilitychange', onDebounce);
      }
    };
  };

  var debouncePageVisible = debouncePageVisibilityFactory();

  var QRCodePromise = function QRCodePromise(parentElement, wwpassURLoptions, ttl, qrcodeStyle) {
    return new Promise(function (resolve) {
      var QRCodeElement = document.createElement('canvas');
      browser.toCanvas(QRCodeElement, getUniversalURL(wwpassURLoptions, false), qrcodeStyle || {}, function (error) {
        if (error) {
          throw error;
        }
      });

      if (qrcodeStyle) {
        QRCodeElement.className = "".concat(qrcodeStyle.prefix, "qrcode_canvas");
        QRCodeElement.style.max_width = "".concat(qrcodeStyle.width, "px");
        QRCodeElement.style.max_height = "".concat(qrcodeStyle.width, "px");
      }

      QRCodeElement.style.height = '100%';
      QRCodeElement.style.width = '100%';

      if (isMobile()) {
        // Wrapping QRCode canvas in <a>
        var universalLinkElement = document.createElement('a');
        universalLinkElement.href = getUniversalURL(wwpassURLoptions);
        universalLinkElement.appendChild(QRCodeElement);
        universalLinkElement.addEventListener('click', function () {
          resolve({
            away: true
          });
        });
        QRCodeElement = universalLinkElement;
      }

      removeLoader(parentElement);
      parentElement.appendChild(QRCodeElement);
      setTimeout(function () {
        debouncePageVisible(function () {
          resolve({
            refresh: true
          });
        });
      }, ttl * 900);
    });
  };

  var clearQRCode = function clearQRCode(parentElement, style) {
    return setLoader(parentElement, style);
  };

  // const DEFAULT_WAIT_CLASS = 'focused';
  // style.transition = 'all .4s ease-out';
  // style.opacity = '.3';

  var PROTOCOL_VERSION = 2;
  /*
   * WWPass QR code auth function
   *
  options = {
      'ticketURL': undefined, // string
      'callbackURL': undefined, // string
      'development': false, // work with dev server
      'log': function (message) || console.log, // another log handler
  }
   */

  var wwpassQRCodeAuth = function wwpassQRCodeAuth(initialOptions) {
    var defaultOptions = {
      universal: false,
      ticketURL: undefined,
      callbackURL: undefined,
      development: false,
      version: 2,
      ppx: 'wwp_',
      spfewsAddress: 'wss://spfews.wwpass.com',
      qrcodeStyle: {
        width: 256,
        prefix: 'wwp_'
      },
      log: function log() {}
    };

    var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

    options.qrcodeStyle = _objectSpread2({}, defaultOptions.qrcodeStyle, {}, initialOptions.qrcodeStyle);
    var log = options.log;

    if (!options.ticketURL) {
      throw Error('ticketURL not found');
    }

    if (!options.callbackURL) {
      throw Error('callbackURL not found');
    }

    if (!options.qrcode) {
      throw Error('Element not found');
    }

    var ticket = null;
    var ttl = null;
    clearQRCode(options.qrcode, options.qrcodeStyle);
    return getTicket(options.ticketURL).then(function (json) {
      var response = ticketAdapter(json);
      ticket = response.ticket;
      ttl = response.ttl;
      return getClientNonceWrapper(ticket, ttl);
    }).then(function (key) {
      var wwpassURLoptions = {
        universal: options.universal,
        ticket: ticket,
        callbackURL: options.callbackURL,
        ppx: options.ppx,
        version: PROTOCOL_VERSION,
        clientKey: key ? encodeClientKey(key) : undefined
      };
      return Promise.race([QRCodePromise(options.qrcode, wwpassURLoptions, ttl, options.qrcodeStyle), getWebSocketResult({
        callbackURL: options.callbackURL,
        ticket: ticket,
        log: log,
        development: options.development,
        version: options.version,
        ppx: options.ppx,
        spfewsAddress: options.spfewsAddress
      })]);
    }).then(function (result) {
      clearQRCode(options.qrcode, options.qrcodeStyle);

      if (result.refresh) {
        return wwpassQRCodeAuth(initialOptions);
      }

      if (result.clientKey && options.catchClientKey) {
        options.catchClientKey(result.clientKey);
      }

      if (result.away) {
        closeConnectionPool();
        return {
          ppx: options.ppx,
          version: options.version,
          status: WWPASS_STATUS.CONTINUE,
          reason: 'User has clicked on QRCode',
          ticket: options.ticket,
          callbackURL: options.callbackURL
        };
      }

      navigateToCallback(result);
      return result;
    })["catch"](function (err) {
      if (!err.status) {
        log('QRCode auth error', err);
        return setRefersh(options.qrcode, err).then(function () {
          clearQRCode(options.qrcode, options.qrcodeStyle);
          return new Promise(function (resolve) {
            setTimeout(function () {
              resolve(wwpassQRCodeAuth(initialOptions));
            }, 500);
          });
        });
      }

      clearQRCode(options.qrcode, options.qrcodeStyle);

      if (err.status === WWPASS_STATUS.INTERNAL_ERROR || options.returnErrors) {
        navigateToCallback(err);
      } else if (err.status === WWPASS_STATUS.TICKET_TIMEOUT) {
        log('ticket timed out');
        return wwpassQRCodeAuth(initialOptions);
      }

      throw err;
    });
  };

  var openWithTicket = function openWithTicket(initialOptions) {
    return new Promise(function (resolve) {
      var defaultOptions = {
        ticket: '',
        ttl: 120,
        callbackURL: '',
        ppx: 'wwp_',
        away: true
      };

      var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

      if (isClientKeyTicket(options.ticket)) {
        generateClientNonce(options.ticket, options.ttl).then(function (key) {
          options = _objectSpread2({}, options, {
            clientKey: encodeClientKey(key)
          });
          var url = getUniversalURL(options);

          if (options.away) {
            window.location.href = url;
          } else {
            resolve(url);
          }
        });
      } else {
        var url = getUniversalURL(options);

        if (options.away) {
          window.location.href = url;
        } else {
          resolve(url);
        }
      }
    });
  };

  var prefix = window.location.protocol === 'https:' ? 'https:' : 'http:';
  var CSS = "".concat(prefix, "//cdn.wwpass.com/packages/wwpass.js/2.4/wwpass.js.css");

  var isNativeMessaging = function isNativeMessaging() {
    var _navigator = navigator,
        userAgent = _navigator.userAgent;
    var re = /Firefox\/([0-9]+)\./;
    var match = userAgent.match(re);

    if (match && match.length > 1) {
      var version = match[1];

      if (Number(version) >= 51) {
        return 'Firefox';
      }
    }

    re = /Chrome\/([0-9]+)\./;
    match = userAgent.match(re);

    if (match && match.length > 1) {
      var _version = match[1];

      if (Number(_version) >= 45) {
        return 'Chrome';
      }
    }

    return false;
  };

  var wwpassPlatformName = function wwpassPlatformName() {
    var _navigator2 = navigator,
        userAgent = _navigator2.userAgent;
    var knownPlatforms = ['Android', 'iPhone', 'iPad'];

    for (var i = 0; i < knownPlatforms.length; i += 1) {
      if (userAgent.search(new RegExp(knownPlatforms[i], 'i')) !== -1) {
        return knownPlatforms[i];
      }
    }

    return null;
  };

  var wwpassMessageForPlatform = function wwpassMessageForPlatform(platformName) {
    return "".concat(WWPASS_UNSUPPORTED_PLATFORM_MSG_TMPL, " ").concat(platformName);
  };

  var wwpassShowError = function wwpassShowError(message, title, onCloseCallback) {
    if (!document.getElementById('_wwpass_css')) {
      var l = document.createElement('link');
      l.id = '_wwpass_css';
      l.rel = 'stylesheet';
      l.href = CSS;
      document.head.appendChild(l);
    }

    var dlg = document.createElement('div');
    dlg.id = '_wwpass_err_dlg';
    var dlgClose = document.createElement('span');
    dlgClose.innerHTML = 'Close';
    dlgClose.id = '_wwpass_err_close';
    var header = document.createElement('h1');
    header.innerHTML = title;
    var text = document.createElement('div');
    text.innerHTML = message;
    dlg.appendChild(header);
    dlg.appendChild(text);
    dlg.appendChild(dlgClose);
    document.body.appendChild(dlg);
    document.getElementById('_wwpass_err_close').addEventListener('click', function () {
      var elem = document.getElementById('_wwpass_err_dlg');
      elem.parentNode.removeChild(elem);
      onCloseCallback();
      return false;
    });
    return true;
  };

  var wwpassNoSoftware = function wwpassNoSoftware(code, onclose) {
    if (code === WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
      var client = isNativeMessaging();
      var message = '';

      if (client) {
        if (client === 'Chrome') {
          var returnURL = encodeURIComponent(window.location.href);
          message = '<p>The WWPass Authentication extension for Chrome is not installed or is disabled in browser settings.';
          message += '<p>Click the link below to install and enable the WWPass Authentication extension.';
          message += "<p><a href=\"https://chrome.wwpass.com/?callbackURL=".concat(returnURL, "\">Install WWPass Authentication Extension</a>");
        } else if (client === 'Firefox') {
          // Firefox
          var _returnURL = encodeURIComponent(window.location.href);

          message = '<p>The WWPass Authentication extension for Firefox is not installed or is disabled in browser settings.';
          message += '<p>Click the link below to install and enable the WWPass Authentication extension.';
          message += "<p><a href=\"https://firefox.wwpass.com/?callbackURL=".concat(_returnURL, "\">Install WWPass Authentication Extension</a>");
        }
      } else {
        message = '<p>No Security Pack is found on your computer or WWPass&nbsp;Browser&nbsp;Plugin is disabled.</p><p>To install Security Pack visit <a href="https://ks.wwpass.com/download/">Key Services</a> or check plugin settings of your browser to activate WWPass&nbsp;Browser&nbsp;Plugin.</p><p><a href="https://support.wwpass.com/?topic=604">Learn more...</a></p>';
      }

      wwpassShowError(message, 'WWPass &mdash; No Software Found', onclose);
    } else if (code === WWPASS_STATUS.UNSUPPORTED_PLATFORM) {
      wwpassShowError(wwpassMessageForPlatform(wwpassPlatformName()), 'WWPass &mdash; Unsupported Platform', onclose);
    }
  };

  var renderPassKeyButton = function renderPassKeyButton() {
    var button = document.createElement('button');
    button.innerHTML = '<svg id="icon-button_logo" viewBox="0 0 34 20" style="fill: none; left: 28px; stroke-width: 2px; width: 35px; height: 25px; top: 5px; position: absolute;"><switch><g><title>button_logo</title><path fill="#FFF" d="M31.2 20h-28c-1.7 0-3-1.3-3-3V3c0-1.7 1.3-3 3-3h27.4C32.5 0 34 1.6 34 3.6c0 1.3-.8 2.5-1.9 3L34 16.8c.2 1.6-.9 3-2.5 3.1-.1.1-.2.1-.3.1zM27 6h-1c-1.1 0-2 .9-2 2v1h-8.3c-.8-2.8-3.8-4.4-6.5-3.5S4.8 9.2 5.6 12s3.8 4.4 6.5 3.5c1.7-.5 3-1.8 3.5-3.5H27V6zm-1 1c-.6 0-1 .4-1 1v2H12.1V8.3c0-.2-.1-.3-.2-.3h-.2l-3.6 2.3c-.1.1-.2.3-.1.4l.1.1 3.6 2.2c.1.1.3 0 .4-.1V11H26V7z"></path></g></switch></svg> Log in with PassKey';
    button.setAttribute('style', 'color: white; background-color: #2277E6; font-weight: 400; font-size: 18px; line-height: 36px; font-family: "Arial", sans-serif; padding-right: 15px; cursor: pointer; height: 40px; width: 255px; border-radius: 3px; border: 1px solid #2277E6; padding-left: 60px; text-decoration: none; position: relative;');
    return button;
  };

  var PLUGIN_OBJECT_ID = '_wwpass_plugin';
  var PLUGIN_MIME_TYPE = 'application/x-wwauth';
  var PLUGIN_TIMEOUT = 10000;
  var REDUCED_PLUGIN_TIMEOUT = 1000;
  var PLUGIN_AUTH_KEYTYPE_REVISION = 9701;
  var PluginInfo = {};
  var savedPluginInstance;
  var pendingReqests = [];

  var havePlugin = function havePlugin() {
    return navigator.mimeTypes[PLUGIN_MIME_TYPE] !== undefined;
  };

  var wwpassPluginShowsErrors = function wwpassPluginShowsErrors(pluginVersionString) {
    if (typeof pluginVersionString === 'string') {
      var pluginVersion = pluginVersionString.split('.');

      for (var i = 0; i < pluginVersion.length; i += 1) {
        pluginVersion[i] = parseInt(pluginVersion[i], 10);
      }

      if (pluginVersion.length === 3) {
        if (pluginVersion[0] > 2 || pluginVersion[0] === 2 && pluginVersion[1] > 4 || pluginVersion[0] === 2 && pluginVersion[1] === 4 && pluginVersion[2] >= 1305) {
          return true;
        }
      }
    }

    return false;
  };

  var getPluginInstance = function getPluginInstance(log) {
    return new Promise(function (resolve, reject) {
      if (savedPluginInstance) {
        if (window._wwpass_plugin_loaded !== undefined) {
          // eslint-disable-line no-underscore-dangle
          pendingReqests.push([resolve, reject]);
        } else {
          log('%s: plugin is already initialized', 'getPluginInstance');
          resolve(savedPluginInstance);
        }
      } else {
        var junkBrowser = navigator.mimeTypes.length === 0;
        var pluginInstalled = havePlugin();
        var timeout = junkBrowser ? REDUCED_PLUGIN_TIMEOUT : PLUGIN_TIMEOUT;

        if (pluginInstalled || junkBrowser) {
          log('%s: trying to create plugin instance(junkBrowser=%s, timeout=%d)', 'getPluginInstance', junkBrowser, timeout);
          var pluginHtml = "<object id='".concat(PLUGIN_OBJECT_ID, "' width=0 height=0 type='").concat(PLUGIN_MIME_TYPE, "'><param name='onload' value='_wwpass_plugin_loaded'/></object>");
          var pluginDiv = document.createElement('div');
          pluginDiv.setAttribute('style', 'position: fixed; left: 0; top:0; width: 1px; height: 1px; z-index: -1; opacity: 0.01');
          document.body.appendChild(pluginDiv);
          pluginDiv.innerHTML += pluginHtml;
          savedPluginInstance = document.getElementById(PLUGIN_OBJECT_ID);
          var timer = setTimeout(function () {
            delete window._wwpass_plugin_loaded; // eslint-disable-line no-underscore-dangle

            savedPluginInstance = null;
            log('%s: WWPass plugin loading timeout', 'getPluginInstance');
            reject({
              code: WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND,
              message: WWPASS_NO_AUTH_INTERFACES_FOUND_MSG
            });

            for (var i = 0; i < pendingReqests.length; i += 1) {
              var pendingReject = pendingReqests[i][1];
              pendingReject({
                code: WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND,
                message: WWPASS_NO_AUTH_INTERFACES_FOUND_MSG
              });
            }
          }, PLUGIN_TIMEOUT);

          window._wwpass_plugin_loaded = function () {
            // eslint-disable-line no-underscore-dangle
            log('%s: plugin loaded', 'getPluginInstance');
            delete window._wwpass_plugin_loaded; // eslint-disable-line no-underscore-dangle

            clearTimeout(timer);

            try {
              PluginInfo.versionString = savedPluginInstance.version;
              PluginInfo.revision = parseInt(savedPluginInstance.version.split('.')[2], 10);
              PluginInfo.showsErrors = wwpassPluginShowsErrors(PluginInfo.versionString);
            } catch (err) {
              log('%s: error parsing plugin version: %s', 'getPluginInstance', err);
            }

            resolve(savedPluginInstance);

            for (var i = 0; i < pendingReqests.length; i += 1) {
              var pendingResolve = pendingReqests[i][0];
              pendingResolve(savedPluginInstance);
            }
          };
        } else {
          log('%s: no suitable plugins installed', 'getPluginInstance');
          reject({
            code: WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND,
            message: WWPASS_NO_AUTH_INTERFACES_FOUND_MSG
          });
        }
      }
    });
  };

  var wrapCallback = function wrapCallback(callback) {
    if (!PluginInfo.showsErrors) {
      return function (code, ticketOrMessage) {
        if (code !== WWPASS_STATUS.OK && code !== WWPASS_STATUS.USER_REJECT) {
          var message = "<p><b>A error has occured:</b> ".concat(ticketOrMessage, "</p>") + "<p><a href=\"https://support.wwpass.com/?topic=".concat(code, "\">Learn more</a></p>");
          wwpassShowError(message, 'WWPass Error', function () {
            callback(code, ticketOrMessage);
          });
        } else {
          callback(code, ticketOrMessage);
        }
      };
    }

    return callback;
  };

  var wwpassPluginExecute = function wwpassPluginExecute(inputRequest) {
    return new Promise(function (resolve, reject) {
      var defaultOptions = {
        log: function log() {}
      };

      var request = _objectSpread2({}, defaultOptions, {}, inputRequest);

      request.log('%s: called, operation name is "%s"', 'wwpassPluginExecute', request.operation || null);
      getPluginInstance(request.log).then(function (plugin) {
        var wrappedCallback = wrapCallback(function (code, ticketOrMessage) {
          if (code === WWPASS_STATUS.OK) {
            resolve(ticketOrMessage);
          } else {
            reject({
              code: code,
              message: ticketOrMessage
            });
          }
        });

        if (plugin.execute !== undefined) {
          request.callback = wrappedCallback;
          plugin.execute(request);
        } else if (request.operation === 'auth') {
          if (PluginInfo.revision < PLUGIN_AUTH_KEYTYPE_REVISION) {
            plugin.authenticate(request.ticket, wrappedCallback);
          } else {
            plugin.authenticate(request.ticket, wrappedCallback, request.firstKeyType || WWPASS_KEY_TYPE_DEFAULT);
          }
        } else {
          plugin.do_operation(request.operation, wrappedCallback);
        }
      })["catch"](reject);
    });
  };

  var pluginWaitForRemoval = function pluginWaitForRemoval() {
    var log = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
    return new Promise(function (resolve, reject) {
      getPluginInstance(log).then(function (plugin) {
        plugin.on_key_removed(resolve);
      })["catch"](reject);
    });
  };

  var EXTENSION_POLL_TIMEOUT = 200;
  var EXTENSION_POLL_ATTEMPTS = 15;
  var extensionNotInstalled = false;

  var timedPoll = function timedPoll(args) {
    var condition = args.condition;

    if (typeof condition === 'function') {
      condition = condition();
    }

    if (condition) {
      args.onCondition();
    } else {
      var attempts = args.attempts || 0;

      if (attempts--) {
        // eslint-disable-line no-plusplus
        var timeout = args.timeout || 100;
        setTimeout(function (p) {
          return function () {
            timedPoll(p);
          };
        }({
          timeout: timeout,
          attempts: attempts,
          condition: args.condition,
          onCondition: args.onCondition,
          onTimeout: args.onTimeout
        }), timeout);
      } else {
        args.onTimeout();
      }
    }
  };

  var isNativeMessagingExtensionReady = function isNativeMessagingExtensionReady() {
    return (document.querySelector('meta[property="wwpass:extension:version"]') || document.getElementById('_WWAuth_Chrome_Installed_')) !== null;
  };

  var randomID = function randomID() {
    return ((1 + Math.random()) * 0x100000000 | 0).toString(16).substring(1);
  }; // eslint-disable-line no-bitwise,max-len


  var wwpassNMCall = function wwpassNMCall(func, args) {
    var log = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : function () {};
    return new Promise(function (resolve, reject) {
      if (extensionNotInstalled) {
        log('%s: chrome native messaging extension is not installed', 'wwpassNMExecute');
        reject({
          code: WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND,
          message: WWPASS_NO_AUTH_INTERFACES_FOUND_MSG
        });
        return;
      }

      timedPoll({
        timeout: EXTENSION_POLL_TIMEOUT,
        attempts: EXTENSION_POLL_ATTEMPTS,
        condition: isNativeMessagingExtensionReady,
        onCondition: function onCondition() {
          var id = randomID();
          window.postMessage({
            type: '_WWAuth_Message',
            src: 'client',
            id: id,
            func: func,
            args: args ? JSON.parse(JSON.stringify(args)) : args
          }, '*');
          window.addEventListener('message', function onMessageCallee(event) {
            if (event.data.type === '_WWAuth_Message' && event.data.src === 'plugin' && event.data.id === id) {
              window.removeEventListener('message', onMessageCallee, false);

              if (event.data.code === WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
                var message = '<p>No Security Pack is found on your computer or WWPass&nbsp;native&nbsp;host is not responding.</p><p>To install Security Pack visit <a href="https://ks.wwpass.com/download/">Key Services</a> </p><p><a href="https://support.wwpass.com/?topic=604">Learn more...</a></p>';
                wwpassShowError(message, 'WWPass Error', function () {
                  reject({
                    code: event.data.code,
                    message: event.data.ticketOrMessage
                  });
                });
              } else if (event.data.code === WWPASS_STATUS.OK) {
                resolve(event.data.ticketOrMessage);
              } else {
                reject({
                  code: event.data.code,
                  message: event.data.ticketOrMessage
                });
              }
            }
          }, false);
        },
        onTimeout: function onTimeout() {
          extensionNotInstalled = true;
          log('%s: chrome native messaging extension is not installed', 'wwpassNMExecute');
          reject({
            code: WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND,
            message: WWPASS_NO_AUTH_INTERFACES_FOUND_MSG
          });
        }
      });
    });
  };

  var wwpassNMExecute = function wwpassNMExecute(inputRequest) {
    var defaultOptions = {
      log: function log() {}
    };

    var request = _objectSpread2({}, defaultOptions, {}, inputRequest);

    var log = request.log;
    delete request.log;
    log('%s: called', 'wwpassNMExecute');
    request.uri = {
      domain: window.location.hostname,
      protocol: window.location.protocol
    };
    return wwpassNMCall('exec', [request], log);
  };

  var nmWaitForRemoval = function nmWaitForRemoval() {
    var log = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
    return wwpassNMCall('on_key_rm', undefined, log);
  };

  var pluginPresent = function pluginPresent() {
    return havePlugin() || isNativeMessagingExtensionReady();
  };

  var wwpassPlatformName$1 = function wwpassPlatformName() {
    var _navigator = navigator,
        userAgent = _navigator.userAgent;
    var knownPlatforms = ['Android', 'iPhone', 'iPad'];

    for (var i = 0; i < knownPlatforms.length; i += 1) {
      if (userAgent.search(new RegExp(knownPlatforms[i], 'i')) !== -1) {
        return knownPlatforms[i];
      }
    }

    return null;
  }; // N.B. it call functions in REVERSE order


  var chainedCall = function chainedCall(functions, request, resolve, reject) {
    functions.pop()(request).then(resolve, function (e) {
      if (e.code === WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
        if (functions.length > 0) {
          chainedCall(functions, request, resolve, reject);
        } else {
          wwpassNoSoftware(e.code, function () {});
          reject(e);
        }
      } else {
        reject(e);
      }
    });
  };

  var wwpassCall = function wwpassCall(nmFunc, pluginFunc, request) {
    return new Promise(function (resolve, reject) {
      var platformName = wwpassPlatformName$1();

      if (platformName !== null) {
        wwpassNoSoftware(WWPASS_STATUS.UNSUPPORTED_PLATFORM, function () {
          reject({
            code: WWPASS_STATUS.UNSUPPORTED_PLATFORM,
            message: wwpassMessageForPlatform(platformName)
          });
        });
        return;
      }

      if (havePlugin()) {
        chainedCall([nmFunc, pluginFunc], request, resolve, reject);
      } else {
        chainedCall([pluginFunc, nmFunc], request, resolve, reject);
      }
    });
  };

  var wwpassAuth = function wwpassAuth(request) {
    return wwpassCall(wwpassNMExecute, wwpassPluginExecute, _objectSpread2({}, request, {
      operation: 'auth'
    }));
  };

  var waitForRemoval = function waitForRemoval() {
    return wwpassCall(nmWaitForRemoval, pluginWaitForRemoval);
  };

  var doWWPassPasskeyAuth = function doWWPassPasskeyAuth(options) {
    return getTicket(options.ticketURL).then(function (json) {
      var response = ticketAdapter(json);
      var ticket = response.ticket;
      return getClientNonceWrapper(ticket, response.ttl).then(function (key) {
        return wwpassAuth({
          ticket: ticket,
          clientKeyNonce: key !== undefined ? abToB64(key) : undefined,
          log: options.log
        });
      }).then(function () {
        return ticket;
      });
      /* We may receive new ticket here but we need
       * to keep the original one to find nonce */
    });
  };

  var wwpassPasskeyAuth = function wwpassPasskeyAuth(initialOptions) {
    return new Promise(function (resolve, reject) {
      var defaultOptions = {
        ticketURL: '',
        callbackURL: '',
        ppx: 'wwp_',
        log: function log() {}
      };

      var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

      if (!options.passkeyButton) {
        reject({
          ppx: options.ppx,
          version: options.version,
          code: WWPASS_STATUS.INTERNAL_ERROR,
          message: 'Cannot find passkey element',
          callbackURL: options.callbackURL
        });
      }

      if (options.passkeyButton.innerHTML.length === 0) {
        options.passkeyButton.appendChild(renderPassKeyButton());
      }

      var authUnderway = false;
      options.passkeyButton.addEventListener('click', function (e) {
        if (!authUnderway) {
          authUnderway = true;
          doWWPassPasskeyAuth(options).then(function (newTicket) {
            authUnderway = false;
            resolve({
              ppx: options.ppx,
              version: options.version,
              code: WWPASS_STATUS.OK,
              message: WWPASS_OK_MSG,
              ticket: newTicket,
              callbackURL: options.callbackURL,
              hw: true
            });
          }, function (err) {
            authUnderway = false;

            if (!err.code) {
              initialOptions.log('passKey error', err);
            } else if (err.code === WWPASS_STATUS.INTERNAL_ERROR || initialOptions.returnErrors) {
              reject({
                ppx: options.ppx,
                version: options.version,
                code: err.code,
                message: err.message,
                callbackURL: options.callbackURL
              });
            }
          });
        }

        e.preventDefault();
      }, false);
    }).then(navigateToCallback, navigateToCallback);
  };

  var absolutePath = function absolutePath(href) {
    var link = document.createElement('a');
    link.href = href;
    return link.href;
  };

  var authInit = function authInit(initialOptions) {
    var defaultOptions = {
      ticketURL: '',
      callbackURL: '',
      hw: false,
      ppx: 'wwp_',
      version: 2,
      log: function log() {}
    };

    var options = _objectSpread2({}, defaultOptions, {}, initialOptions);

    options.callbackURL = absolutePath(options.callbackURL);
    options.passkeyButton = typeof options.passkey === 'string' ? document.querySelector(options.passkey) : options.passkey;
    options.qrcode = typeof options.qrcode === 'string' ? document.querySelector(options.qrcode) : options.qrcode;
    var promises = [];

    if (options.passkeyButton) {
      promises.push(wwpassPasskeyAuth(options));
    }

    promises.push(wwpassQRCodeAuth(options));
    return Promise.race(promises);
  };

  var version$1 = "1.0.0";

  if ('console' in window && window.console.log) {
    window.console.log("WWPass frontend library version ".concat(version$1));
  }

  window.WWPass = {
    authInit: authInit,
    openWithTicket: openWithTicket,
    isClientKeyTicket: isClientKeyTicket,
    cryptoPromise: WWPassCryptoPromise,
    copyClientNonce: copyClientNonce,
    updateTicket: updateTicket,
    pluginPresent: pluginPresent,
    waitForRemoval: waitForRemoval,
    STATUS: WWPASS_STATUS
  };

}());
//# sourceMappingURL=wwpass-frontend.js.map
