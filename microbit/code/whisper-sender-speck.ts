// ============================================================
//  WHISPER NETWORK · SPECK-64/128 SENDER  (complexity comparison)
//  ----------------------------------------------------------
//  Same job as the HMAC-SHA256 hardened sender: deliver the day
//  key confidentially. The point of this file is the CIPHER below.
//
//  CODE-SIZE COMPARISON
//    SHA-256 + HMAC library ....... ~110 lines
//    Speck-64/128 (whole cipher) ...  ~15 lines  (the two functions below)
//  Speck's round is add-rotate-xor on two 32-bit words -- a native
//  fit for the micro:bit, and something a capable student can write.
//  Verified: this exact code reproduces the official Speck-64/128
//  test vector (see verify_ciphers.js).
//
//  Caveat kept honest: Speck (like Simon) is NSA-designed and ISO
//  declined to standardize it in 2018; no practical break exists on
//  full-round Speck, so it is fine for this classroom threat model.
// ============================================================

let CHANNEL = 7
let CELL = 1
let TXPOWER = 2      // low power shrinks the eavesdropping radius

// 128-bit pre-shared cell key as four 32-bit words [k0, l0, l1, l2]
let CELLKEY = [0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918]
// 128-bit day key (four words) the instructor injects
let DAYKEY = [0xc796632a, 0x11ff0158, 0x49406fde, 0x21be0780]

// ---------- Speck-64/128 : the entire cipher ----------
function ror(x: number, r: number): number { return ((x >>> r) | (x << (32 - r))) >>> 0 }
function rol(x: number, r: number): number { return ((x << r) | (x >>> (32 - r))) >>> 0 }

function speckExpand(K: number[]): number[] {          // -> 27 round keys
    let l = [K[1], K[2], K[3]]
    let k = [K[0]]
    for (let i = 0; i <= 25; i++) {
        l[i + 3] = (((k[i] + ror(l[i], 8)) >>> 0) ^ i) >>> 0
        k[i + 1] = (rol(k[i], 3) ^ l[i + 3]) >>> 0
    }
    return k
}
function speckEncrypt(rk: number[], x: number, y: number): number[] {   // 64-bit block
    for (let i = 0; i < 27; i++) {
        x = (((ror(x, 8) + y) >>> 0) ^ rk[i]) >>> 0
        y = (rol(y, 3) ^ x) >>> 0
    }
    return [x >>> 0, y >>> 0]
}
// ------------------------------------------------------

radio.setGroup(CHANNEL)
radio.setTransmitPower(TXPOWER)
basic.showString("S")

input.onButtonPressed(Button.A, function () {
    let rk = speckExpand(CELLKEY)
    let IV = Math.randomRange(0, 2147483647)      // per-seed nonce (use a unique IV each time)

    // CTR mode: two 64-bit keystream blocks -> four 32-bit words, XOR the day key
    let b0 = speckEncrypt(rk, IV, 0)
    let b1 = speckEncrypt(rk, IV, 1)
    let C = [
        (DAYKEY[0] ^ b0[0]) >>> 0, (DAYKEY[1] ^ b0[1]) >>> 0,
        (DAYKEY[2] ^ b1[0]) >>> 0, (DAYKEY[3] ^ b1[1]) >>> 0
    ]

    // send IV + ciphertext in two fragments, repeated for reliability
    for (let rep = 0; rep < 3; rep++) {
        let p1 = pins.createBuffer(14)            // [1][cell][IV][C0][C1]
        p1.setUint8(0, 1); p1.setUint8(1, CELL)
        p1.setNumber(NumberFormat.UInt32BE, 2, IV)
        p1.setNumber(NumberFormat.UInt32BE, 6, C[0])
        p1.setNumber(NumberFormat.UInt32BE, 10, C[1])
        radio.sendBuffer(p1)
        basic.pause(40)

        let p2 = pins.createBuffer(10)            // [2][cell][C2][C3]
        p2.setUint8(0, 2); p2.setUint8(1, CELL)
        p2.setNumber(NumberFormat.UInt32BE, 2, C[2])
        p2.setNumber(NumberFormat.UInt32BE, 6, C[3])
        radio.sendBuffer(p2)
        basic.pause(40)
    }
    basic.showIcon(IconNames.Yes)
})

// Note: this shows CONFIDENTIALITY (encryption). To also AUTHENTICATE the seed
// (the encrypt-then-MAC the HMAC sender did), add a Speck-CMAC under a second key
// -- about a dozen more lines, still far shorter than SHA-256. For the challenge
// response, the responder simply computes speckEncrypt(dayKeyExpanded, nonceHi, nonceLo)
// as its proof: the block cipher doubles as the MAC, so no HMAC is needed anywhere.
