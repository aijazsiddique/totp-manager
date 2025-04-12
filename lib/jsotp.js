/*
 * jsOTP - A TOTP/HOTP library implementation in JavaScript
 * https://github.com/jiangts/JS-OTP
 * 
 * Modified and simplified for Chrome extension use
 */

// Dependencies (base32 and jsSHA included inline)

// Base32 Encoding/Decoding
const base32 = {
    encode: function(s) {
      const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const pad = "=";
      const len = s.length;
      const o = [];
      let i = 0;
      let n = 0;
      let t = 0;
  
      while (i < len) {
        t = s.charCodeAt(i);
        n = (n << 8) | t;
        
        i += 1;
        
        if ((i % 5) === 0 || i === len) {
          const offset = ((i % 5) * 8) % 40;
          
          if (offset === 0) {
            o.push(a.charAt((n >> 35) & 31));
            o.push(a.charAt((n >> 30) & 31));
            o.push(a.charAt((n >> 25) & 31));
            o.push(a.charAt((n >> 20) & 31));
            o.push(a.charAt((n >> 15) & 31));
            o.push(a.charAt((n >> 10) & 31));
            o.push(a.charAt((n >> 5) & 31));
            o.push(a.charAt(n & 31));
          } else if (offset === 8) {
            o.push(a.charAt((n >> 27) & 31));
            o.push(a.charAt((n >> 22) & 31));
            o.push(a.charAt((n >> 17) & 31));
            o.push(a.charAt((n >> 12) & 31));
            o.push(a.charAt((n >> 7) & 31));
            o.push(a.charAt((n >> 2) & 31));
            o.push(pad);
            o.push(pad);
          } else if (offset === 16) {
            o.push(a.charAt((n >> 19) & 31));
            o.push(a.charAt((n >> 14) & 31));
            o.push(a.charAt((n >> 9) & 31));
            o.push(a.charAt((n >> 4) & 31));
            o.push(a.charAt((n << 1) & 31));
            o.push(pad);
            o.push(pad);
            o.push(pad);
          } else if (offset === 24) {
            o.push(a.charAt((n >> 11) & 31));
            o.push(a.charAt((n >> 6) & 31));
            o.push(a.charAt((n >> 1) & 31));
            o.push(a.charAt((n << 4) & 31));
            o.push(pad);
            o.push(pad);
            o.push(pad);
            o.push(pad);
          } else if (offset === 32) {
            o.push(a.charAt((n >> 3) & 31));
            o.push(a.charAt((n << 2) & 31));
            o.push(pad);
            o.push(pad);
            o.push(pad);
            o.push(pad);
            o.push(pad);
            o.push(pad);
          }
          
          n = 0;
        }
      }
      
      return o.join("");
    },
    
    decode: function(s) {
      const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const len = s.length;
      let n = 0;
      let j = 0;
      let e = 0;
      let pad = 0;
      const t = [];
      let o = "";
      
      for (let i = 0; i < len; i++) {
        const v = a.indexOf(s.charAt(i).toUpperCase());
        
        if (v >= 0) {
          n = (n << 5) | v;
          e += 5;
          
          if (e >= 8) {
            t[j] = (n >> (e - 8)) & 255;
            j += 1;
            e -= 8;
          }
        } else if (s.charAt(i) !== "=") {
          // Invalid base32 character
          throw new Error("Invalid base32 character in string");
        } else {
          pad += 1;
        }
      }
      
      for (let i = 0; i < t.length; i++) {
        o += String.fromCharCode(t[i]);
      }
      
      return o;
    }
  };
  
  // jsSHA for HMAC-SHA1
  /*
   * A JavaScript implementation of the SHA family of hashes, as
   * defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
   * HMAC implementation as defined in FIPS PUB 198a
   *
   * Copyright 2008-2020 Brian Turek, 1998-2009 Paul Johnston & Contributors
   * Distributed under the BSD License
   * See http://caligatio.github.com/jsSHA/ for more information
   */
  class jsSHA {
    constructor(variant, inputFormat, options) {
      this.variant = variant.toLowerCase();
      this.inputFormat = inputFormat.toLowerCase();
      
      this.utfType = "UTF8";
      this.numRounds = 1;
      
      if (options) {
        if (options.encoding) this.utfType = options.encoding;
        if (options.numRounds) this.numRounds = options.numRounds;
      }
      
      this.shaObj = null;
      this.hmacKeySet = false;
      
      if (this.variant === "sha-1") {
        this.blockBytes = 64;
        this.outputBits = 160;
        this.isVariableLen = false;
      } else {
        throw new Error("Chosen SHA variant is not supported");
      }
      
      this.state = {
        h0: 0x67452301,
        h1: 0xEFCDAB89,
        h2: 0x98BADCFE,
        h3: 0x10325476,
        h4: 0xC3D2E1F0
      };
      
      this.buffer = [];
      this.processedLen = 0;
      this.inputBlocks = [];
      this.remainder = [];
    }
  
    /* Public Methods */
    
    update(srcString) {
      let utf8Str = this._convertToBytes(srcString);
      let input = utf8Str;
      
      this.remainder = [];
      
      if (this.inputBlocks.length > 0) {
        // We have a remainder from previous update, prepend to current input
        input = this.inputBlocks.concat(input);
      }
      
      // Process blocks (64 bytes each)
      for (let i = 0; i + this.blockBytes <= input.length; i += this.blockBytes) {
        const block = input.slice(i, i + this.blockBytes);
        this._processBlock(block);
        this.processedLen += this.blockBytes;
      }
      
      // Save remainder
      if (input.length % this.blockBytes > 0) {
        this.remainder = input.slice(input.length - (input.length % this.blockBytes));
      }
      
      this.inputBlocks = this.remainder;
      
      return this;
    }
    
    getHash(outputFormat, options) {
      const formatOpts = options || {};
      
      // Process the rest of the input
      const finalBlock = this._finalizeInput();
      this._processBlock(finalBlock);
      
      const hash = this._getHMAC();
      
      // Format the output
      let formattedOutput = "";
      
      if (outputFormat === "hex") {
        for (let i = 0; i < this.outputBits / 8; i++) {
          formattedOutput += ((hash[i] >>> 4) & 0xf).toString(16);
          formattedOutput += (hash[i] & 0xf).toString(16);
        }
        return formattedOutput;
      } else if (outputFormat === "b64") {
        // Base64 encoding not implemented for this simplified version
        throw new Error("Base64 output format not implemented");
      } else {
        return hash;
      }
    }
    
    setHMACKey(key, inputFormat, options) {
      const formatOpts = options || {};
      
      if (!key) {
        throw new Error("HMAC key cannot be empty");
      }
      
      let keyBytes = this._convertToBytes(key);
      
      // Reset state before setting key
      this.reset();
      
      // If key is longer than block size, hash it
      if (keyBytes.length > this.blockBytes) {
        const hasher = new jsSHA(this.variant, "ARRAYBUFFER");
        hasher.update(keyBytes);
        keyBytes = hasher.getHash("ARRAYBUFFER");
      }
      
      // Keys shorter than blockBytes are zero-padded
      if (keyBytes.length < this.blockBytes) {
        const tmp = new Array(this.blockBytes);
        for (let i = 0; i < this.blockBytes; i++) {
          tmp[i] = 0;
        }
        for (let i = 0; i < keyBytes.length; i++) {
          tmp[i] = keyBytes[i];
        }
        keyBytes = tmp;
      }
      
      // Prepare the key for the HMAC process
      const ipad = new Array(this.blockBytes);
      const opad = new Array(this.blockBytes);
      
      for (let i = 0; i < this.blockBytes; i++) {
        ipad[i] = keyBytes[i] ^ 0x36;
        opad[i] = keyBytes[i] ^ 0x5c;
      }
      
      // Update with the ipad
      this.update(ipad);
      
      // Store opad for later
      this.opad = opad;
      
      this.hmacKeySet = true;
      
      return this;
    }
    
    /* Private Methods */
    
    _processBlock(block) {
      // Prepare message schedule
      const w = new Array(80);
      
      // Convert byte array to 32-bit word array
      for (let i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | 
               (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
      }
      
      // Extend to 80 words
      for (let i = 16; i < 80; i++) {
        w[i] = this._rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      }
      
      // Initialize hash value for this chunk
      let a = this.state.h0;
      let b = this.state.h1;
      let c = this.state.h2;
      let d = this.state.h3;
      let e = this.state.h4;
      
      // Main loop
      for (let i = 0; i < 80; i++) {
        let f, k;
        
        if (i < 20) {
          f = (b & c) | ((~b) & d);
          k = 0x5A827999;
        } else if (i < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (i < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }
        
        const temp = (this._rotl(a, 5) + f + e + k + w[i]) & 0xffffffff;
        e = d;
        d = c;
        c = this._rotl(b, 30);
        b = a;
        a = temp;
      }
      
      // Add this chunk's hash to result so far
      this.state.h0 = (this.state.h0 + a) & 0xffffffff;
      this.state.h1 = (this.state.h1 + b) & 0xffffffff;
      this.state.h2 = (this.state.h2 + c) & 0xffffffff;
      this.state.h3 = (this.state.h3 + d) & 0xffffffff;
      this.state.h4 = (this.state.h4 + e) & 0xffffffff;
    }
    
    _rotl(x, n) {
      return (x << n) | (x >>> (32 - n));
    }
    
    _finalizeInput() {
      // Prepare the final block (with length)
      const totalBitsLen = (this.processedLen + this.remainder.length) * 8;
      
      // Add '1' bit
      this.remainder.push(0x80);
      
      // Add padding zeros to make room for the length
      const blockByteLen = this.blockBytes;
      
      // 56 = 64 - 8 (room for length bits)
      while (this.remainder.length < 56) {
        this.remainder.push(0);
      }
      
      // Add length as 64-bit big-endian integer
      const lengthBits = [
        0, 0, 0, 0,
        (totalBitsLen >>> 24) & 0xff,
        (totalBitsLen >>> 16) & 0xff,
        (totalBitsLen >>> 8) & 0xff,
        totalBitsLen & 0xff
      ];
      
      return this.remainder.concat(lengthBits);
    }
    
    _getHMAC() {
      // Convert state to byte array
      const hashBytes = new Array(this.outputBits / 8);
      
      // Copy the state values back into hashBytes
      for (let i = 0; i < 5; i++) {
        const stateVal = this.state["h" + i];
        hashBytes[i * 4] = (stateVal >>> 24) & 0xff;
        hashBytes[i * 4 + 1] = (stateVal >>> 16) & 0xff;
        hashBytes[i * 4 + 2] = (stateVal >>> 8) & 0xff;
        hashBytes[i * 4 + 3] = stateVal & 0xff;
      }
      
      if (this.hmacKeySet) {
        // HMAC => (key XOR opad) || H((key XOR ipad) || message)
        const hmac = new jsSHA(this.variant, "ARRAYBUFFER");
        hmac.update(this.opad);
        hmac.update(hashBytes);
        return hmac.getHash("ARRAYBUFFER");
      } else {
        return hashBytes;
      }
    }
    
    _convertToBytes(input) {
      if (typeof input === "string") {
        return this._stringToBytes(input);
      } else if (input instanceof Array) {
        return input;
      } else if (input instanceof Uint8Array) {
        const arr = new Array(input.length);
        for (let i = 0; i < input.length; i++) {
          arr[i] = input[i];
        }
        return arr;
      } else {
        throw new Error("Input format not recognized");
      }
    }
    
    _stringToBytes(str) {
      const byteArray = [];
      
      for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        
        if (code < 128) {
          byteArray.push(code);
        } else if (code < 2048) {
          byteArray.push((code >> 6) | 192);
          byteArray.push((code & 63) | 128);
        } else if (code < 65536) {
          byteArray.push((code >> 12) | 224);
          byteArray.push(((code >> 6) & 63) | 128);
          byteArray.push((code & 63) | 128);
        } else {
          byteArray.push((code >> 18) | 240);
          byteArray.push(((code >> 12) & 63) | 128);
          byteArray.push(((code >> 6) & 63) | 128);
          byteArray.push((code & 63) | 128);
        }
      }
      
      return byteArray;
    }
    
    reset() {
      this.state = {
        h0: 0x67452301,
        h1: 0xEFCDAB89,
        h2: 0x98BADCFE,
        h3: 0x10325476,
        h4: 0xC3D2E1F0
      };
      
      this.buffer = [];
      this.processedLen = 0;
      this.inputBlocks = [];
      this.remainder = [];
      
      return this;
    }
  }
  
  // HOTP implementation
  class HOTP {
    constructor(secret) {
      this.secret = secret;
      this.digits = 6;
    }
    
    generate(counter) {
      // Convert counter to bytes
      const counterBytes = new Array(8);
      for (let i = 7; i >= 0; i--) {
        counterBytes[i] = counter & 0xff;
        counter = counter >>> 8;
      }
      
      // Decode the secret from base32
      let key;
      try {
        key = base32.decode(this.secret);
      } catch (e) {
        throw new Error("Invalid base32 secret");
      }
      
      // Convert key to byte array
      const keyBytes = [];
      for (let i = 0; i < key.length; i++) {
        keyBytes.push(key.charCodeAt(i));
      }
      
      // Calculate HMAC-SHA1
      const hmacSha = new jsSHA("SHA-1", "ARRAYBUFFER");
      hmacSha.setHMACKey(keyBytes, "ARRAYBUFFER");
      hmacSha.update(counterBytes);
      const hmac = hmacSha.getHash("ARRAYBUFFER");
      
      // Dynamic truncation
      const offset = hmac[19] & 0xf;
      const binary = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);
      
      // Modulo and pad
      const otp = binary % Math.pow(10, this.digits);
      return otp.toString().padStart(this.digits, '0');
    }
  }
  
  // TOTP implementation
  class TOTP {
    constructor(secret) {
      this.secret = secret;
      this.hotp = new HOTP(secret);
      this.period = 30; // Default time step in seconds
    }
    
    generate(timestamp = null) {
      const time = timestamp ? Math.floor(timestamp / 1000) : Math.floor(Date.now() / 1000);
      const counter = Math.floor(time / this.period);
      return this.hotp.generate(counter);
    }
    
    getRemainingSeconds() {
      const now = Math.floor(Date.now() / 1000);
      return this.period - (now % this.period);
    }
    
    getRemainingPercentage() {
      const remaining = this.getRemainingSeconds();
      return (remaining / this.period) * 100;
    }
    
    verify(token, timestamp = null, window = 1) {
      const time = timestamp ? Math.floor(timestamp / 1000) : Math.floor(Date.now() / 1000);
      const counter = Math.floor(time / this.period);
      
      // Check in time window
      for (let i = -window; i <= window; i++) {
        const generatedToken = this.hotp.generate(counter + i);
        if (generatedToken === token) {
          return true;
        }
      }
      
      return false;
    }
  }
  
  // Export the TOTP class
  window.TOTP = TOTP;
