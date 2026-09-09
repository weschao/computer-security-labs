// Verify Speck-64/128, AES-128, and X25519 against official test vectors.
const crypto = require('crypto');
let pass = 0, fail = 0;
function ck(name, got, want) {
  const ok = got === want;
  console.log((ok ? 'PASS ' : 'FAIL ') + name);
  if (!ok) { console.log('   got : ' + got); console.log('   want: ' + want); fail++; } else pass++;
}
const hx = x => ('00000000' + (x >>> 0).toString(16)).slice(-8);

// ================= SPECK 64/128 (32-bit words, micro:bit-portable ops) =================
const ror = (x, r) => ((x >>> r) | (x << (32 - r))) >>> 0;
const rol = (x, r) => ((x << r) | (x >>> (32 - r))) >>> 0;

// key K = [k0, l0, l1, l2]  (k0 = least-significant key word)
function speckExpand(K) {
  let l = [K[1], K[2], K[3]];
  let k = [K[0]];
  for (let i = 0; i <= 25; i++) {            // T-2 = 25
    l[i + 3] = (((k[i] + ror(l[i], 8)) >>> 0) ^ i) >>> 0;
    k[i + 1] = (rol(k[i], 3) ^ l[i + 3]) >>> 0;
  }
  return k;                                   // 27 round keys
}
function speckEncrypt(rk, x, y) {
  for (let i = 0; i < 27; i++) {
    x = (((ror(x, 8) + y) >>> 0) ^ rk[i]) >>> 0;
    y = (rol(y, 3) ^ x) >>> 0;
  }
  return [x >>> 0, y >>> 0];
}

console.log('=== Speck-64/128 (official test vector, Simon & Speck spec) ===');
// key 1b1a1918 13121110 0b0a0908 03020100 ; pt 3b726574 7475432d ; ct 8c6fa548 454e028b
const Kspeck = [0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918];
const rk = speckExpand(Kspeck);
const [cx, cy] = speckEncrypt(rk, 0x3b726574, 0x7475432d);
ck('Speck64/128 encrypt block', hx(cx) + ' ' + hx(cy), '8c6fa548 454e028b');
// round-trip sanity via a decrypt
function speckDecrypt(rk, x, y) {
  for (let i = 26; i >= 0; i--) {
    y = (rol((y ^ x) >>> 0, 32 - 3)) >>> 0;      // inverse of y = ROL(y,3)^x
    x = ((((x ^ rk[i]) >>> 0) - y) >>> 0);
    x = rol(x, 8);                                // inverse of x = ROR(x,8)+y (then rotate back)
  }
  return [x >>> 0, y >>> 0];
}
const [px, py] = speckDecrypt(rk, cx, cy);
ck('Speck64/128 decrypt round-trips', hx(px) + ' ' + hx(py), '3b726574 7475432d');

// ================= AES-128 (FIPS-197 Appendix C.1) =================
console.log('\n=== AES-128 ECB (FIPS-197 C.1) -- confirms the device self-test target ===');
{
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const pt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const c = crypto.createCipheriv('aes-128-ecb', key, null); c.setAutoPadding(false);
  const ct = Buffer.concat([c.update(pt), c.final()]).toString('hex');
  ck('AES-128 encrypt block', ct, '69c4e0d86a7b0430d8cdb78070b4c55a');
}

// ================= X25519 (RFC 7748) via BigInt reference =================
console.log('\n=== X25519 / Curve25519 ECDH (RFC 7748) ===');
const P = (1n << 255n) - 19n;
const A24 = 121665n;
function bytesToBigLE(b){ let x=0n; for(let i=b.length-1;i>=0;i--) x=(x<<8n)|BigInt(b[i]); return x; }
function bigToBytesLE(x){ const b=Buffer.alloc(32); for(let i=0;i<32;i++){ b[i]=Number(x & 255n); x>>=8n; } return b; }
function decodeScalar(hex){ const a=Buffer.from(hex,'hex'); a[0]&=248; a[31]&=127; a[31]|=64; return bytesToBigLE(a); }
function decodeU(hex){ const a=Buffer.from(hex,'hex'); a[31]&=127; return bytesToBigLE(a)%P; }
function modpow(b,e,m){ let r=1n; b%=m; while(e>0n){ if(e&1n) r=(r*b)%m; b=(b*b)%m; e>>=1n; } return r; }
const mod=(x)=>((x%P)+P)%P;
function x25519(scalarHex, uHex){
  const k=decodeScalar(scalarHex); const x1=decodeU(uHex);
  let x2=1n,z2=0n,x3=x1,z3=1n,swap=0n;
  for(let t=254;t>=0;t--){
    const kt=(k>>BigInt(t))&1n;
    swap^=kt;
    if(swap){ [x2,x3]=[x3,x2]; [z2,z3]=[z3,z2]; }
    swap=kt;
    const A=mod(x2+z2), AA=mod(A*A);
    const B=mod(x2-z2), BB=mod(B*B);
    const E=mod(AA-BB);
    const C=mod(x3+z3), D=mod(x3-z3);
    const DA=mod(D*A), CB=mod(C*B);
    x3=mod(mod(DA+CB)*mod(DA+CB));
    z3=mod(x1*mod(mod(DA-CB)*mod(DA-CB)));
    x2=mod(AA*BB);
    z2=mod(E*mod(AA+mod(A24*E)));
  }
  if(swap){ [x2,x3]=[x3,x2]; [z2,z3]=[z3,z2]; }
  const res=mod(x2*modpow(z2,P-2n,P));
  return bigToBytesLE(res).toString('hex');
}
// RFC 7748 section 5.2 single scalarmult vector
ck('X25519 scalarmult KAT',
  x25519('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
         'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'),
  'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');

// RFC 7748 section 6.1 -- full Diffie-Hellman (this is exactly on-device provisioning)
const base = '0900000000000000000000000000000000000000000000000000000000000000';
const alicePriv='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
const bobPriv  ='5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
const alicePub=x25519(alicePriv, base);
const bobPub  =x25519(bobPriv, base);
ck('Alice public key from private', alicePub, '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
ck('Bob public key from private',   bobPub,   'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
const sharedA=x25519(alicePriv, bobPub);
const sharedB=x25519(bobPriv, alicePub);
ck('ECDH: Alice(bobPub) == shared secret', sharedA, '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
ck('ECDH: both sides agree', sharedA, sharedB);

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
