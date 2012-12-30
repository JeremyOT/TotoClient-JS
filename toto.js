//////////////////////// from jsSHA - sha1.js /////////////////////////////

/* A JavaScript implementation of the SHA family of hashes, as defined in FIPS
* PUB 180-2 as well as the corresponding HMAC implementation as defined in
* FIPS PUB 198a
*
* Version 1.3 Copyright Brian Turek 2008-2010
* Distributed under the BSD License
* See http://jssha.sourceforge.net/ for more information
*
* Several functions taken from Paul Johnson
*/
(
  function() {
    var charSize = 8, b64pad = "", hexCase = 0, str2binb = function(a) {
      var b = [], mask = (1 << charSize) - 1, length = a.length * charSize, i;
      for( i = 0; i < length; i += charSize) {
        b[i >> 5] |= (a.charCodeAt(i / charSize) & mask) << (32 - charSize - (i % 32))
      }
      return b
    }, hex2binb = function(a) {
      var b = [], length = a.length, i, num;
      for( i = 0; i < length; i += 2) {
        num = parseInt(a.substr(i, 2), 16);
        if(!isNaN(num)) {
          b[i >> 3] |= num << (24 - (4 * (i % 8)))
        } else {
          return "INVALID HEX STRING"
        }
      }
      return b
    }, binb2hex = function(a) {
      var b = (hexCase) ? "0123456789ABCDEF" : "0123456789abcdef", str = "", length = a.length * 4, i, srcByte;
      for( i = 0; i < length; i += 1) {
        srcByte = a[i >> 2] >> ((3 - (i % 4)) * 8);
        str += b.charAt((srcByte >> 4) & 0xF) + b.charAt(srcByte & 0xF)
      }
      return str
    }, binb2b64 = function(a) {
      var b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789+/", str = "", length = a.length * 4, i, j, triplet;
      for( i = 0; i < length; i += 3) {
        triplet = (((a[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) | (((a[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) | ((a[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
        for( j = 0; j < 4; j += 1) {
          if(i * 8 + j * 6 <= a.length * 32) {
            str += b.charAt((triplet >> 6 * (3 - j)) & 0x3F)
          } else {
            str += b64pad
          }
        }
      }
      return str
    }, rotl = function(x, n) {
      return (x << n) | (x >>> (32 - n))
    }, parity = function(x, y, z) {
      return x ^ y ^ z
    }, ch = function(x, y, z) {
      return (x & y) ^ (~x & z)
    }, maj = function(x, y, z) {
      return (x & y) ^ (x & z) ^ (y & z)
    }, safeAdd_2 = function(x, y) {
      var a = (x & 0xFFFF) + (y & 0xFFFF), msw = (x >>> 16) + (y >>> 16) + (a >>> 16);
      return ((msw & 0xFFFF) << 16) | (a & 0xFFFF)
    }, safeAdd_5 = function(a, b, c, d, e) {
      var f = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) + (e & 0xFFFF), msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (f >>> 16);
      return ((msw & 0xFFFF) << 16) | (f & 0xFFFF)
    }, coreSHA1 = function(f, g) {
      var W = [], a, b, c, d, e, T, i, t, appendedMessageLength, H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], K = [0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6];
      f[g >> 5] |= 0x80 << (24 - (g % 32));
      f[(((g + 65) >> 9) << 4) + 15] = g;
      appendedMessageLength = f.length;
      for( i = 0; i < appendedMessageLength; i += 16) {
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        for( t = 0; t < 80; t += 1) {
          if(t < 16) {
            W[t] = f[t + i]
          } else {
            W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1)
          }
          if(t < 20) {
            T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, K[t], W[t])
          } else if(t < 40) {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t])
          } else if(t < 60) {
            T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, K[t], W[t])
          } else {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t])
          }
          e = d;
          d = c;
          c = rotl(b, 30);
          b = a;
          a = T
        }
        H[0] = safeAdd_2(a, H[0]);
        H[1] = safeAdd_2(b, H[1]);
        H[2] = safeAdd_2(c, H[2]);
        H[3] = safeAdd_2(d, H[3]);
        H[4] = safeAdd_2(e, H[4])
      }
      return H
    }, jsSHA = function(a, b) {
      this.sha1 = null;
      this.strBinLen = null;
      this.strToHash = null;
      if("HEX" === b) {
        if(0 !== (a.length % 2)) {
          return "TEXT MUST BE IN BYTE INCREMENTS"
        }
        this.strBinLen = a.length * 4;
        this.strToHash = hex2binb(a)
      } else if(("ASCII" === b) || ('undefined' === typeof (b))) {
        this.strBinLen = a.length * charSize;
        this.strToHash = str2binb(a)
      } else {
        return "UNKNOWN TEXT INPUT TYPE"
      }
    };
    jsSHA.prototype = {
      getHash : function(a) {
        var b = null, message = this.strToHash.slice();
        switch(a) {
          case"HEX":
            b = binb2hex;
            break;
          case"B64":
            b = binb2b64;
            break;
          default:
            return "FORMAT NOT RECOGNIZED"
        }
        if(null === this.sha1) {
          this.sha1 = coreSHA1(message, this.strBinLen)
        }
        return b(this.sha1)
      },
      getHMAC : function(a, b, c) {
        var d, keyToUse, i, retVal, keyBinLen, keyWithIPad = [], keyWithOPad = [];
        switch(c) {
          case"HEX":
            d = binb2hex;
            break;
          case"B64":
            d = binb2b64;
            break;
          default:
            return "FORMAT NOT RECOGNIZED"
        }
        if("HEX" === b) {
          if(0 !== (a.length % 2)) {
            return "KEY MUST BE IN BYTE INCREMENTS"
          }
          keyToUse = hex2binb(a);
          keyBinLen = a.length * 4
        } else if("ASCII" === b) {
          keyToUse = str2binb(a);
          keyBinLen = a.length * charSize
        } else {
          return "UNKNOWN KEY INPUT TYPE"
        }
        if(64 < (keyBinLen / 8)) {
          keyToUse = coreSHA1(keyToUse, keyBinLen);
          keyToUse[15] &= 0xFFFFFF00
        } else if(64 > (keyBinLen / 8)) {
          keyToUse[15] &= 0xFFFFFF00
        }
        for( i = 0; i <= 15; i += 1) {
          keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
          keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C
        }
        retVal = coreSHA1(keyWithIPad.concat(this.strToHash), 512 + this.strBinLen);
        retVal = coreSHA1(keyWithOPad.concat(retVal), 672);
        return (d(retVal))
      }
    };
    window.jsSHA = jsSHA
  }());

//////////////////////// end sha1.js /////////////////////////////

(
  function() {

    var Future = (function() {

      var FutureInitialized = 0, FutureFinished = 1, FutureFailed = 2;

      function Future() {
        this._state = FutureInitialized;
        this._onError = [];
        this._onFinish = [];
        this._result = null;
      };

      Future.prototype.finish = function() {
        this._result = arguments;
        this._state = FutureFinished;
        for(var i = 0; i < this._onFinish.length; i++) {
          this._onFinish[i].apply(null, this._result);
        }
      };

      Future.prototype.fail = function() {
        this._result = arguments;
        this._state = FutureFailed;
        for(var i = 0; i < this._onError.length; i++) {
          this._onError[i].apply(null, this._result);
        }
      };

      Future.prototype.then = function(handler) {
        this._onFinish.push(handler);
        if(this._state == FutureFinished) {
          handler.apply(null, this._result);
        }
        return this;
      };

      Future.prototype.error = function(handler) {
        this._onError.push(handler);
        if(this._state == FutureFailed) {
          handler.apply(null, this._result);
        }
        return this;
      };

      return Future;
    })();

    var TotoSocket = (function() {

      var SocketInitialized = 0, SocketOpen = 1, SocketClosed = 2;

      function TotoSocket(url, toto) {
        this._url = url;
        this._onClosed = null;
        this._onOpen = null;
        this._onMessage = null;
        this._onMessageId = {};
        this._state = SocketInitialized;
        this._toto = toto;
        this._socket = null;
      };

      TotoSocket.prototype.onOpen = function(handler) {
        this._onOpen = handler;
        if(this._state == SocketOpen) {
          handler(this);
        }
        return this;
      };

      TotoSocket.prototype.onClosed = function(handler) {
        this._onClosed = handler;
        if(this._state == SocketClosed) {
          handler(this);
        }
        return this;
      };

      TotoSocket.prototype.onMessage = function(messageId, handler) {
        if(messageId) {
          this._onMessageId['messageId'] = handler;
        } else {
          this._onMessage = handler;
        }
        return this;
      };

      TotoSocket.prototype.open = function(authenticated) {
        if(authenticated) {
          if(!this._url.charAt(this._url.length - 1) == '/') {
            this._url += '/';
          }
          this._url += sessionValue("TOTO_SESSION_ID" + this._toto.url);
        }
        var totoSocket = this;
        totoSocket._socket = new WebSocket(this._url);
        totoSocket._socket.onopen = function() {
          totoSocket._state = SocketOpen;
          if(totoSocket._onOpen) {
            totoSocket._onOpen();
          }
        };
        totoSocket._socket.onclosed = function() {
          totoSocket._state = SocketClosed;
          if(totoSocket._onClosed) {
            totoSocket._onClosed();
          }
        };
        totoSocket._socket.onmessage = function(event) {
          var message = JSON.parse(event.data);
          if(message.message_id && totoSocket._onMessageId[message.message_id]) {
            totoSocket._onMessageId[message.message_id](message.data);
          } else if(totoSocket._onMessage) {
            totoSocket._onMessage(message);
          }
        };
      };

      TotoSocket.prototype.close = function() {
        this._socket.close();
      }

      TotoSocket.prototype.send = function(method, params) {
        this._socket.send(JSON.stringify({
          method : method,
          parameters : params
        }));
      }

      return TotoSocket;
    })();

    function Toto(url, options) {
      options = options || {};
      options.url = url;
      for(var k in options)
      this[k] = options[k];
      this.batchQueue = {};
      this.socket = null;
      this.socketMessageHandlers = {};
    };

    var localStorageDisabled = false;
    function sessionValue(name) {
      if(!localStorageDisabled) {
        try {
          return localStorage[name];
        } catch (e) {
          localStorageDisabled = true;
        }
      }
      return;
      var match = new RegExp(name + '=(.+?);').exec(document.cookie);
      if(!match) {
        return null;
      }
      return match[1];
    };

    function setSessionValue(name, value) {
      if(!localStorageDisabled) {
        try {
          localStorage[name] = value;
          return;
        } catch (e) {
          localStorageDisabled = true;
        }
      }
      var re = new RegExp(name + '=(.+?);'), match = re.exec(document.cookie), newVal = value ? [name, '=', value, ';'].join('') : '', cookie = document.cookie;
      if (match) {
        document.cookie = cookie.replace(re, newVal);
      } else if (value) {
        document.cookie = newVal + cookie;
      }
    };

    Toto.prototype.sessionID = function() {
      var session = sessionValue("TOTO_SESSION_ID" + this.url), sessionExpires = sessionValue("TOTO_SESSION_EXPIRES" + this.url);
      return sessionExpires > (new Date().getTime() / 1000.0) && session;
    };

    Toto.prototype.userID = function() {
      return sessionValue("TOTO_USER_ID" + this.url);
    };

    Toto.prototype.hmac = function(body) {
      var userID = this.userID(), hmac = null;
      if(userID) {
        hmac = new jsSHA(body, "ASCII").getHMAC(userID, "ASCII", "B64");
        switch(hmac.length % 4) {
          case 2:
            return hmac + "==";
          case 3:
            return hmac + "=";
        }
      }
      return hmac;
    };

    Toto.prototype.request = function(method, args) {
      return this.rawRequest({
        "method" : method,
        "parameters" : args
      });
    };

    Toto.prototype.rawRequest = function(object) {
      var body = JSON.stringify(object), toto = this, session = this.sessionID(), hmac = session && this.hmac(body), xhr = window.XMLHttpRequest && new XMLHttpRequest(), future = new Future();
      if(!xhr) {
        try {
          xhr = new ActiveXObject("Msxml2.XMLHTTP");
        } catch (e) {
          xhr = new ActiveXObject("Microsoft.XMLHTTP");
        }
      }
      xhr.onreadystatechange = function() {
        if(this.readyState == 4 && this.status == 200) {
          var response = JSON.parse(this.responseText), responseHmac = this.getResponseHeader("x-toto-hmac"), userID = toto.userID();
          if(responseHmac && userID && toto.hmac(this.responseText) != responseHmac) {
            response.error = {
              "value" : "Invalid response HMAC",
              "code" : 1009
            };
          }
          if(response.error) {
            if (response.error.code == 1004) {
              toto.logout();
            }
            future.fail(response.error, this);
          } else {
            if(response.session) {
              var originalUserID = toto.userID();
              setSessionValue("TOTO_SESSION_ID" + toto.url, response.session.session_id);
              setSessionValue("TOTO_SESSION_EXPIRES" + toto.url, response.session.expires);
              setSessionValue("TOTO_USER_ID" + toto.url, response.session.user_id);
              if (originalUserID != response.session.user_id) {
                toto.userStateChanged(response.session.user_id);
              }
            }
            future.finish(response.batch || response.result, this);
          }
        } else if (this.readyState == 4) {
          var error = {
            "value" : this.responseText,
            "code" : this.status
          };
          future.fail(error, this);
        }
      };
      xhr.open("POST", this.url);
      if(hmac) {
        xhr.setRequestHeader("x-toto-session-id", session);
        xhr.setRequestHeader("x-toto-hmac", hmac);
      }
      xhr.setRequestHeader("content-type", "application/json");
      xhr.send(body);
      return future;
    };
    Toto.prototype.logout = function() {
      setSessionValue("TOTO_USER_ID" + this.url, '');
      setSessionValue("TOTO_SESSION_ID" + this.url, '');
      setSessionValue("TOTO_SESSION_EXPIRES" + this.url, '');
      this.userStateChanged();
    };
    Toto.prototype.userStateChanged = function(arg) {
      if (typeof arg === 'function') {
        this.onUserStateChanged = arg;
      } else if (typeof arg === 'null') {
        delete this.onUserStateChanged;
      } else if (typeof arg === 'undefined') {
        if (this.onUserStateChanged) {
          this.onUserStateChanged(this.userID());
        }
      } else if (this.onUserStateChanged) {
        this.onUserStateChanged(arg);
      }
    };
    // method is optional, defaults to 'client_error'
    Toto.prototype.registerErrorHandler = function(method) {
      if(!method)
        method = 'client_error';
      baseHandler = window.onerror;
      var toto = this;
      window.onerror = function(message, file, line) {
        if(baseHandler)
          baseHandler(message, file, line);
        toto.request(method, {
          'client_error' : {
            'message' : message,
            'file' : file,
            'line' : line,
            'user_agent' : navigator.userAgent
          },
          'client_type' : 'browser_js'
        });
      }
    };

    Toto.prototype.queueRequest = function(id, method, args) {
      var future = new Future();
      this.batchQueue[id] = {
        'method' : method,
        'parameters' : args,
        'future' : future
      };
      return future;
    };

    Toto.prototype.batchRequest = function() {
      var batchRequestQueue = this.batchQueue, batch = {}, future = new Future();
      this.batchQueue = {};
      for(var id in batchRequestQueue) {
        var request = batchRequestQueue[id];
        batch[id] = {
          'method' : request['method'],
          'parameters' : request['parameters']
        };
      }
      var callback = function(batchResponse, xhr) {
        for(var id in batchResponse) {
          var response = batchResponse[id];
          if(response.error) {
            batchRequestQueue[id]['future'].fail(response.error, xhr);
          } else {
            batchRequestQueue[id]['future'].finish(response.result, xhr);
          }
        }
        future.finish();
      };
      this.rawRequest({
        'batch' : batch
      }).then(callback).error(callback);
      return future;
    };

    Toto.prototype.socketSupported = function() {
      return !!window.WebSocket;
    };

    function convertToSocketUrl(url, path) {
      var a = document.createElement('a');
      a.href = url + (path.charAt(0) == '/' ? path : '/' + path);
      return a.href.replace(/^http/i, 'ws');
    }


    Toto.prototype.createSocket = function(path) {
      if(!this.socketSupported()) {
        return null;
      }
      var socketUrl = path && (path.indexOf('ws://') == 0 || path.indexOf('wss://') == 0) ? path : convertToSocketUrl(this.url, path || 'websocket');
      return new TotoSocket(socketUrl, this);
    };

    Toto.prototype.registerRemoteWorker = function(path) {
      if(!this.socketSupported() || this._remoteWorkerSocket) {
        return;
      }
      var socketUrl = path && (path.indexOf('ws://') == 0 || path.indexOf('wss://') == 0) ? path : convertToSocketUrl(this.url, path || 'remoteworker');
      this._remoteWorkerSocket = new TotoSocket(socketUrl, this);
      var socket = this._remoteWorkerSocket;
      socket.onMessage(null, function(task) {
        var finishHandler = function(data) {
          socket._socket.send(JSON.stringify({
            operation_id : task.operation_id,
            result : data
          }));
        };
        eval('(' + task.script + ')')(finishHandler);
      });
      socket.open();
    };

    window.Toto = Toto;
  })();
