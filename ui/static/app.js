

var testKey = document.querySelector('#secret-key').textContent;
var testPassphrase = document.querySelector('#key-passphrase').value;

var generateIdFixOrigin = function () {
  // https://github.com/jvehent/idfix#51origin-string
  var now = new Date();
  now.setMilliseconds(0);
  var isoNow = now.toISOString().replace('.000Z', 'Z');
  var nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce, 16);
  // Chrome doesn't support typed array join so convert to a regular array first
  nonce = Array.prototype.slice.call(nonce).join("");
  return '1;' + isoNow + ';' + nonce; //  + ';'; in the spec but not used by MIG yet
};

var message = generateIdFixOrigin();

var secretKey = openpgp.key.readArmored(testKey);
if (secretKey.err) {
    window.alert("Error decrypting secret key: " + secretKey.err[0]);
}
secretKey = secretKey.keys[0];

console.log("got secretKey", secretKey);
var decryptStart = window.performance.now();
secretKey.decrypt(testPassphrase);
console.log("decrypted secretKey in:", window.performance.now() - decryptStart);

var detachSig = function (sig) {
  var sigLines = sig.split('\n')
      .map(function (l) {
	return l.replace('\r', '');
      })
      .filter(function (l) {
	  return (l !== '' && l.substring(0, '-----'.length) !==  '-----');
      });

  // Drop the first four lines e.g.
  // 'Hash: SHA256',
  // '1;2015-04-08T05:37:53Z;jr3i14bIkRvlNtYzq+mV4w==',
  // 'Version: OpenPGP.js VERSION',
  //   'Comment: http://openpgpjs.org',
      return sigLines.slice(4).join('').replace('\n', '');
};


var sendXHR = function (method, url, authHeader) {
  function reqListener () {
    console.log(this.responseText);
  };
  var xhr = new XMLHttpRequest();
  xhr.open(method, url, true);
  console.log("using auth header:", authHeader);
  xhr.setRequestHeader("X-PGPAUTHORIZATION", authHeader);
  xhr.onload = reqListener;
  xhr.send();
};

message = '1;2015-06-01T23:54:54Z;471552042256425119417744262292222481247';

var signStart = window.performance.now();
console.log("signing: ", message);

var detachedSig = null;
openpgp.signClearMessage(secretKey, message)
  .then(function (sig) {
    console.log("signed in:", window.performance.now() - signStart);
    console.log(sig);
    detachedSig = detachSig(sig);
    console.log(detachedSig);
    sendXHR("GET", "http://localhost:12345/api/v1/investigator\?investigatorid\=3", message + ';' + detachedSig);
  })
  .catch(function () {
    console.log("There was an error signing the message.", arguments);
  });
