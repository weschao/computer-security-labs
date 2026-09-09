// Verify a micro:bit-portable SHA-256 / HMAC-SHA256 against official
// known-answer vectors, then simulate the full Whisper Network protocol.
// Uses ONLY operations available in MakeCode Static TypeScript:
//   32-bit bitwise ( & | ^ ~ << >> >>> ), array indexing, loops.
// Bytes are modeled as arrays of 0..255 (like a micro:bit Buffer).

const K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

// SHA-256 over an array of bytes -> array of 32 bytes
function sha256(bytes) {
  let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const l = bytes.length;
  const m = bytes.slice();
  m.push(0x80);
  while (m.length % 64 !== 56) m.push(0);
  const bitLenHi = Math.floor(l / 0x20000000);   // (l*8) >> 32, safe for our small inputs
  const bitLen = (l * 8) >>> 0;
  m.push((bitLenHi >>> 24) & 0xff, (bitLenHi >>> 16) & 0xff, (bitLenHi >>> 8) & 0xff, bitLenHi & 0xff);
  m.push((bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);

  const W = new Array(64);
  for (let off = 0; off < m.length; off += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = ((m[off+4*t]<<24) | (m[off+4*t+1]<<16) | (m[off+4*t+2]<<8) | (m[off+4*t+3])) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(W[t-15],7) ^ rotr(W[t-15],18) ^ (W[t-15] >>> 3)) >>> 0;
      const s1 = (rotr(W[t-2],17) ^ rotr(W[t-2],19) ^ (W[t-2] >>> 10)) >>> 0;
      W[t] = (((W[t-16] + s0) >>> 0) + ((W[t-7] + s1) >>> 0)) >>> 0;
    }
    let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)) >>> 0;
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const temp1 = (((h + S1) >>> 0) + ((ch + ((K[t] + W[t]) >>> 0)) >>> 0)) >>> 0;
      const S0 = (rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d + temp1) >>> 0; d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = [];
  for (let i = 0; i < 8; i++) out.push((H[i]>>>24)&0xff,(H[i]>>>16)&0xff,(H[i]>>>8)&0xff,H[i]&0xff);
  return out;
}

// HMAC-SHA256(key bytes, msg bytes) -> 32 bytes
function hmac(key, msg) {
  const B = 64;
  let k = key.slice();
  if (k.length > B) k = sha256(k);
  while (k.length < B) k.push(0);
  const ipad = [], opad = [];
  for (let i = 0; i < B; i++) { ipad.push(k[i]^0x36); opad.push(k[i]^0x5c); }
  return sha256(opad.concat(sha256(ipad.concat(msg))));
}

// helpers
const hex = a => a.map(b => ('0'+(b&0xff).toString(16)).slice(-2)).join('');
const str = s => Array.from(Buffer.from(s, 'utf8'));

let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  console.log((ok ? 'PASS ' : 'FAIL ') + name);
  if (!ok) { console.log('   got : ' + got); console.log('   want: ' + want); fail++; } else pass++;
}

console.log('=== SHA-256 known-answer vectors (FIPS 180-4) ===');
check('SHA256("")',    hex(sha256(str(""))),    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
check('SHA256("abc")', hex(sha256(str("abc"))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
check('SHA256("abc"x...448bit)', hex(sha256(str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');

console.log('\n=== HMAC-SHA256 known-answer vectors (RFC 4231) ===');
// Test Case 2
check('HMAC("Jefe", "what do ya want for nothing?")',
      hex(hmac(str("Jefe"), str("what do ya want for nothing?"))),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
// Test Case 1: key = 0x0b x20, data = "Hi There"
check('HMAC(0x0b*20, "Hi There")',
      hex(hmac(new Array(20).fill(0x0b), str("Hi There"))),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');

console.log('\n=== Full Whisper Network protocol simulation ===');
// XOR helper
const xor = (a,b) => a.map((v,i)=>v^b[i]);
const take = (a,n) => a.slice(0,n);

// Shared cell key (established out-of-band), 128-bit
const CELLKEY = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
// The day's random key the instructor injects, 128-bit
const DAYKEY  = [200,150,99,42,17,255,1,88,73,64,111,222,33,190,7,128];

// --- Sender: encrypt-then-MAC the day key under CELLKEY ---
const IV = [11,22,33,44,55,66,77,88];                          // random per seed
const keystream = take(hmac(CELLKEY, [0x00].concat(IV)), 16);  // domain 0x00
const C = xor(DAYKEY, keystream);                               // ciphertext
const TAG = take(hmac(CELLKEY, [0x01].concat(IV).concat(C)), 8); // domain 0x01, auth

// --- Responder: verify tag, then decrypt ---
const TAG2 = take(hmac(CELLKEY, [0x01].concat(IV).concat(C)), 8);
check('seed authentication tag matches', hex(TAG), hex(TAG2));
const recovered = xor(C, take(hmac(CELLKEY, [0x00].concat(IV)), 16));
check('responder recovers the day key', hex(recovered), hex(DAYKEY));

// tamper test: flip one ciphertext byte -> tag must fail
const Cbad = C.slice(); Cbad[0] ^= 0x01;
const TAGbad = take(hmac(CELLKEY, [0x01].concat(IV).concat(Cbad)), 8);
check('tampered seed is rejected (tags differ)', (hex(TAG) !== hex(TAGbad)) ? 'rejected' : 'accepted', 'rejected');

// --- Challenge / response with serial binding ---
const NONCE = [9,8,7,6,5,4,3,2,1,0,255,254];        // 96-bit, fresh from Checker
const SERIAL_LEGIT = [0xDE,0xAD,0xBE,0xEF];          // responder's device serial (4 bytes)
const SERIAL_SPY   = [0x13,0x37,0x00,0x01];          // a rival device's serial

// legit responder computes response over nonce + ITS OWN serial (domain 0x02)
const R = take(hmac(DAYKEY, [0x02].concat(NONCE).concat(SERIAL_LEGIT)), 12);
// checker recomputes for the serial it actually saw on the packet
const expectLegit = take(hmac(DAYKEY, [0x02].concat(NONCE).concat(SERIAL_LEGIT)), 12);
check('legit device response accepted', (hex(R)===hex(expectLegit))?'accept':'reject', 'accept');

// RELAY ATTACK: spy replays the legit device's response R, but the packet
// now carries the spy's serial. Checker recomputes with the spy's serial.
const expectSpy = take(hmac(DAYKEY, [0x02].concat(NONCE).concat(SERIAL_SPY)), 12);
check('relayed response rejected (serial binding)', (hex(R)===hex(expectSpy))?'accept':'reject', 'reject');

// FORGERY without key: spy guesses a response for the victim cell
const RForge = take(hmac([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], [0x02].concat(NONCE).concat(SERIAL_SPY)), 12);
check('forgery without the key rejected', (hex(RForge)===hex(expectSpy))?'accept':'reject', 'reject');

// LEGIT +5: a spy that ACTUALLY stole DAYKEY can answer for this cell with its own serial
const RSteal = take(hmac(DAYKEY, [0x02].concat(NONCE).concat(SERIAL_SPY)), 12);
check('true key theft DOES let a foreign device answer (+5 earned honestly)',
      (hex(RSteal)===hex(expectSpy))?'accept':'reject', 'accept');

console.log('\n=== SUMMARY ===');
console.log(pass + ' passed, ' + fail + ' failed');
process.exit(fail === 0 ? 0 : 1);
