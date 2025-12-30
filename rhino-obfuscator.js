// Rhino-friendly obfuscation helper (global, not a module)
var SecureRandom = Java.type("java.security.SecureRandom");
var MessageDigest = Java.type("java.security.MessageDigest");
var Cipher = Java.type("javax.crypto.Cipher");
var SecretKeyFactory = Java.type("javax.crypto.SecretKeyFactory");
var GCMParameterSpec = Java.type("javax.crypto.spec.GCMParameterSpec");
var PBEKeySpec = Java.type("javax.crypto.spec.PBEKeySpec");
var SecretKeySpec = Java.type("javax.crypto.spec.SecretKeySpec");
var Base64 = Java.type("java.util.Base64");
var StandardCharsets = Java.type("java.nio.charset.StandardCharsets");
var ByteArray = Java.type("byte[]");
var GLOBAL = this;

  var BYTE_SEEDS = [
    0x10A, 0x2F, 0x5C, 0xA5, 0xF1, 0x3B, 0x7C, 0x9D, 0xE2, 0x55, 0x6A, 0x8E, 0xC3, 0xD4, 0x1F, 0x2A,
    0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x19, 0x2B, 0x3C, 0x4E,
    0x5F, 0x6B, 0x7D, 0x8F, 0x90, 0xA1, 0xB2, 0xC6, 0xD7, 0xE8, 0xF9, 0x0A, 0x1B, 0x2C, 0x3D, 0x4F,
    0x5A, 0x6C, 0x7E, 0x8A, 0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1, 0xF2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7A, 0x8B, 0x9E, 0xAF, 0xC0, 0xD1, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B,
    0x6D, 0x7F, 0x80, 0x93, 0xA4, 0xB5, 0xC7, 0xD8, 0xE9, 0xFA, 0x0B, 0x1C, 0x2D, 0x3E, 0x4C, 0x5D,
    0x6E, 0x7B, 0x8C, 0x9F, 0xAE, 0xBF, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38, 0x49, 0x5A, 0x6B,
    0x7C, 0x8D, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67,
    0x78, 0x89, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF3, 0x04, 0x15, 0x26, 0x37, 0x48, 0x59, 0x6A,
    0x7D, 0x8E, 0x9D, 0xAE, 0xBF, 0xC1, 0xD3, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D,
    0x7E, 0x8F, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E,
    0x7F, 0x82, 0x94, 0xA6, 0xB8, 0xCA, 0xDC, 0xEE, 0x0C, 0x1D, 0x2E, 0x3F, 0x40, 0x51, 0x62, 0x73,
    0x84, 0x95, 0xA7, 0xB9, 0xCB, 0xDD, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x57, 0x68, 0x79, 0x8A, 0x9B,
    0xAD, 0xBE, 0xCF, 0xD9, 0xEA, 0xFB, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C, 0x6F, 0x81, 0x92, 0xA3,
    0xB6, 0xC8, 0xDA, 0xEC, 0xFE, 0x0F, 0x20, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xA8, 0xB9,
    0xCA, 0xDB, 0xED, 0xFF, 0x13, 0x24, 0x35, 0x46, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE, 0xCF
  ];

  function toBytes(str) {
    return str == null ? new ByteArray(0) : str.getBytes(StandardCharsets.UTF_8);
  }

  function decodeBase64Url(data) {
    return Base64.getUrlDecoder().decode(data);
  }

  function encodeBase64Url(bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  function randomBytes(size) {
    var buf = new ByteArray(size);
    new SecureRandom().nextBytes(buf);
    return buf;
  }

  function deriveKey(secret, salt) {
    var factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    var spec = new PBEKeySpec(secret.toCharArray(), salt, 160000, 256);
    var key = factory.generateSecret(spec).getEncoded();
    spec.clearPassword();
    return key;
  }

  function checksum(bytes, salt) {
    var digest = MessageDigest.getInstance("SHA-256");
    digest.update(bytes);
    if (salt) {
      digest.update(salt);
    }
    var hash = digest.digest();
    return encodeBase64Url(hash);
  }

  function encrypt(source, secret) {
    var salt = randomBytes(16);
    var iv = randomBytes(12);
    var key = new SecretKeySpec(deriveKey(secret, salt), "AES");
    var cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    var body = cipher.doFinal(toBytes(source));
    var tag = checksum(body, salt);
    return {
      s: encodeBase64Url(salt),
      v: encodeBase64Url(iv),
      p: encodeBase64Url(body),
      h: tag
    };
  }

  function decrypt(blob, secret) {
    var salt = decodeBase64Url(blob.s);
    var iv = decodeBase64Url(blob.v);
    var payload = decodeBase64Url(blob.p);
    var key = new SecretKeySpec(deriveKey(secret, salt), "AES");
    var cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    var plainBytes = cipher.doFinal(payload);
    return new java.lang.String(plainBytes, StandardCharsets.UTF_8);
  }

  function wrapPayload(parts) {
    var noise = encodeBase64Url(randomBytes(24));
    var chaff = encodeBase64Url(randomBytes(24));
    var stride = Math.max(3, new SecureRandom().nextInt(6) + 3); // 3-8
    var shift = new SecureRandom().nextInt(15) + 1; // 1-15
    var inner = JSON.stringify({
      n: noise,
      c: chaff,
      t: stride,
      x: shift,
      s: parts.s,
      v: parts.v,
      p: parts.p,
      h: parts.h,
      k: parts.k || null
    });
    var confused = inner.split("").reverse().join("");
    var shifted = confused.replace(/[A-Za-z]/g, function (c) {
      var base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 7) % 26) + base);
    });
    var rotated = encodeBase64Url(toBytes(shifted)).split("").map(function (ch) {
      var code = ch.charCodeAt(0);
      return String.fromCharCode(code ^ shift);
    }).join("");
    var byteLayer = scrambleBytes(rotated);
    var filler = encodeBase64Url(randomBytes(32));
    var hintBytes = new ByteArray(2);
    hintBytes[0] = (shift + 64);
    hintBytes[1] = (stride + 64);
    var hint = encodeBase64Url(hintBytes);
    var interleaved = interleave(byteLayer, filler + hint, stride);
    return interleaved;
  }

  function unwrapPayload(b64) {
    var extracted = deinterleave(b64);
    var decoded = unscrambleBytes(extracted.payload);
    var shift = extracted.shift;
    var json = decoded.split("").map(function (ch) {
      var code = ch.charCodeAt(0);
      return String.fromCharCode(code ^ shift);
    }).join("");
    json = new java.lang.String(decodeBase64Url(json), StandardCharsets.UTF_8);
    var unshifted = json.replace(/[A-Za-z]/g, function (c) {
      var base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 26 - 7) % 26) + base);
    });
    var restored = unshifted.split("").reverse().join("");
    return JSON.parse(restored);
  }

  function obfuscate(source, secret) {
    var blob = encrypt(source, secret);
    return wrapPayload(blob);
  }

  function generateSecret(sizeBytes) {
    var size = sizeBytes && sizeBytes > 0 ? sizeBytes : 32;
    return encodeBase64Url(randomBytes(size));
  }

  function obfuscateSelfContained(source) {
    var embeddedKeyBytes = randomBytes(32);
    var embeddedKey = encodeBase64Url(embeddedKeyBytes);
    var blob = encrypt(source, embeddedKey);
    blob.k = scrambleBytes(embeddedKey);
    return wrapPayload(blob);
  }

  function deobfuscate(bundle, secret) {
    var blob = unwrapPayload(bundle);
    if (!blob || !blob.h || !blob.p || !blob.s) {
      throw new Error("Invalid obfuscation bundle");
    }
    var plaintext = decrypt(blob, secret);
    var recalculated = checksum(decodeBase64Url(blob.p), decodeBase64Url(blob.s));
    if (recalculated !== blob.h) {
      throw new Error("Tampered obfuscation payload");
    }
    return plaintext;
  }

  function runSelfContained(bundle, scope) {
    var blob = unwrapPayload(bundle);
    if (!blob.k) {
      throw new Error("No embedded secret present");
    }
    var embeddedSecret = unscrambleBytes(blob.k);
    var plaintext = decrypt(blob, embeddedSecret);
    var recalculated = checksum(decodeBase64Url(blob.p), decodeBase64Url(blob.s));
    if (recalculated !== blob.h) {
      throw new Error("Tampered obfuscation payload");
    }
    var host = GLOBAL || this;
    var sandbox = scope || {};
    for (var key in sandbox) {
      if (sandbox.hasOwnProperty(key)) {
        host[key] = sandbox[key];
      }
    }
    try {
      (new Function("with(this){" + plaintext + "}")).call(host);
    } finally {
      for (var cleanupKey in sandbox) {
        if (sandbox.hasOwnProperty(cleanupKey)) {
          try {
            delete host[cleanupKey];
          } catch (e) {
            host[cleanupKey] = undefined;
          }
        }
      }
    }
  }

  function runObfuscated(bundle, secret, scope) {
    var code = deobfuscate(bundle, secret);
    var host = GLOBAL || this;
    var sandbox = scope || {};
    for (var key in sandbox) {
      if (sandbox.hasOwnProperty(key)) {
        host[key] = sandbox[key];
      }
    }
    try {
      (new Function("with(this){" + code + "}")).call(host);
    } finally {
      for (var cleanupKey in sandbox) {
        if (sandbox.hasOwnProperty(cleanupKey)) {
          try {
            delete host[cleanupKey];
          } catch (e) {
            host[cleanupKey] = undefined;
          }
        }
      }
    }
  }

  // convenience aliases for easier usage
  function bundle(source, secret) {
    return obfuscate(source, secret);
  }

  function runBundle(bundleData, secret, scope) {
    return runObfuscated(bundleData, secret, scope);
  }

  function seal(source) {
    return obfuscateSelfContained(source);
  }

  function runSealed(bundleData, scope) {
    return runSelfContained(bundleData, scope);
  }

  function packAndRun(source, secret, scope) {
    var b = obfuscate(source, secret);
    return runObfuscated(b, secret, scope);
  }

  function scrambleBytes(text) {
    var bytes = toBytes(text);
    for (var i = 0; i < bytes.length; i++) {
      var seed = BYTE_SEEDS[i % BYTE_SEEDS.length];
      var mask = ((seed ^ (i * 0x1F) ^ 0x10A) + 0x5A) & 0xFF;
      bytes[i] = (bytes[i] ^ mask ^ 0x3D) & 0xFF;
    }
    return encodeBase64Url(bytes);
  }

  function unscrambleBytes(encoded) {
    var bytes = decodeBase64Url(encoded);
    for (var i = 0; i < bytes.length; i++) {
      var seed = BYTE_SEEDS[i % BYTE_SEEDS.length];
      var mask = ((seed ^ (i * 0x1F) ^ 0x10A) + 0x5A) & 0xFF;
      var val = (bytes[i] & 0xFF) ^ mask ^ 0x3D;
      bytes[i] = val & 0xFF;
    }
    return new java.lang.String(bytes, StandardCharsets.UTF_8);
  }

  function interleave(data, filler, stride) {
    var out = [];
    var cursor = 0;
    for (var i = 0; i < data.length; i++) {
      out.push(data.charAt(i));
      if ((i + 1) % stride === 0 && cursor < filler.length) {
        out.push(filler.charAt(cursor++));
      }
    }
    while (cursor < filler.length) {
      out.push(filler.charAt(cursor++));
    }
    return out.join("");
  }

  function deinterleave(obscured) {
    var chars = obscured.split("");
    var metadata = [];
    var payload = [];
    // extract metadata encoded at even positions near the end
    for (var i = 0; i < chars.length; i++) {
      if (i % 2 === 0) {
        payload.push(chars[i]);
      } else {
        metadata.push(chars[i]);
      }
    }
    // attempt to recover stride and shift hints encoded in metadata tail
    var hintRaw = metadata.slice(-8).join("");
    var hintBytes;
    try {
      hintBytes = decodeBase64Url(hintRaw);
    } catch (e) {
      hintBytes = new ByteArray(0);
    }
    var stride = 4;
    var shift = 5;
    if (hintBytes.length >= 2) {
      var decodedShift = (hintBytes[0] & 0xFF) - 64;
      var decodedStride = (hintBytes[1] & 0xFF) - 64;
      stride = Math.max(3, decodedStride);
      shift = Math.max(1, decodedShift);
    }
    return { payload: payload.join(""), stride: stride, shift: shift };
  }

var api = {
  obfuscate: obfuscate,
  deobfuscate: deobfuscate,
  runObfuscated: runObfuscated,
  generateSecret: generateSecret,
  obfuscateSelfContained: obfuscateSelfContained,
  runSelfContained: runSelfContained,
  bundle: bundle,
  runBundle: runBundle,
  seal: seal,
  runSealed: runSealed,
  packAndRun: packAndRun
};

// Expose globally (non-module usage)
var RhinoObfuscator = api;
