// ============================================================
//  WHISPER NETWORK · HARDENED SENDER
//  >>> Paste the contents of whisper-crypto-lib.ts ABOVE this. <<<
//
//  Delivers the day's 128-bit key CONFIDENTIALLY and AUTHENTICALLY:
//    ciphertext C = DAYKEY XOR HMAC(CELLKEY, 0x00 || IV)
//    tag         = HMAC(CELLKEY, 0x01 || IV || C)   (encrypt-then-MAC)
//  Eavesdroppers see only IV, C, tag -- none of which reveal the key.
//  A forged/tampered seed fails the tag, so a spoofed "Oracle" is rejected.
//  Transmitted at LOW power in two 18-byte packets. Press A to seed.
// ============================================================

let CHANNEL = 7
let CELL = 1
let TXPOWER = 2      // low power shrinks the eavesdropping radius (defense in depth)

// CELLKEY: 128-bit pre-shared key, agreed IN PERSON before class.
// In a real round, load this out-of-band (button entry / provisioning) so it is
// NOT present in the source you submit publicly. Shown inline here for testing.
let CELLKEY = [0x8f, 0x21, 0x6c, 0xa3, 0x0b, 0xd4, 0x77, 0x19, 0xe2, 0x55, 0x3a, 0x90, 0xc1, 0x4e, 0x88, 0x02]

// DAYKEY: the fresh 128-bit secret the instructor injects this morning.
let DAYKEY = [0xc7, 0x96, 0x63, 0x2a, 0x11, 0xff, 0x01, 0x58, 0x49, 0x40, 0x6f, 0xde, 0x21, 0xbe, 0x07, 0x80]

radio.setGroup(CHANNEL)
radio.setTransmitPower(TXPOWER)
basic.showString("S")

function randByte(): number { return Math.randomRange(0, 255) }

input.onButtonPressed(Button.A, function () {
    // fresh 64-bit IV
    let IV: number[] = []
    for (let i = 0; i < 8; i++) IV.push(randByte())

    // keystream = HMAC(CELLKEY, 0x00 || IV), first 16 bytes
    let ksIn: number[] = [0x00]
    for (let i = 0; i < 8; i++) ksIn.push(IV[i])
    let ks = hmac(CELLKEY, ksIn)

    // ciphertext
    let C: number[] = []
    for (let i = 0; i < 16; i++) C.push(DAYKEY[i] ^ ks[i])

    // authentication tag = HMAC(CELLKEY, 0x01 || IV || C), first 8 bytes
    let tagIn: number[] = [0x01]
    for (let i = 0; i < 8; i++) tagIn.push(IV[i])
    for (let i = 0; i < 16; i++) tagIn.push(C[i])
    let tag = take(hmac(CELLKEY, tagIn), 8)

    // send twice-fragmented (18 bytes each), repeated for reliability
    for (let rep = 0; rep < 3; rep++) {
        let p1 = pins.createBuffer(18)      // [1][cell][IV 8][C[0..7]]
        p1.setUint8(0, 1); p1.setUint8(1, CELL)
        for (let i = 0; i < 8; i++) p1.setUint8(2 + i, IV[i])
        for (let i = 0; i < 8; i++) p1.setUint8(10 + i, C[i])
        radio.sendBuffer(p1)
        basic.pause(40)

        let p2 = pins.createBuffer(18)      // [2][cell][C[8..15]][tag 8]
        p2.setUint8(0, 2); p2.setUint8(1, CELL)
        for (let i = 0; i < 8; i++) p2.setUint8(2 + i, C[8 + i])
        for (let i = 0; i < 8; i++) p2.setUint8(10 + i, tag[i])
        radio.sendBuffer(p2)
        basic.pause(40)
    }
    basic.showIcon(IconNames.Yes)
})
