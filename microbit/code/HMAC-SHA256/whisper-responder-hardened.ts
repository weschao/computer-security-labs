// ============================================================
//  WHISPER NETWORK · HARDENED RESPONDER
//  >>> Paste the contents of whisper-crypto-lib.ts ABOVE this. <<<
//
//  (1) Receives the encrypted seed, VERIFIES the tag, DECRYPTS the day key.
//  (2) On challenge, replies HMAC(DAYKEY, 0x02 || nonce || ownSerial), 12 bytes.
//
//  Why it is safe to answer any challenge:
//    - HMAC reveals nothing about the key (it is a PRF), so answering freely
//      cannot leak DAYKEY -- this kills the "signing oracle" worry.
//    - The response is BOUND TO THIS DEVICE'S SERIAL, so a relayed answer only
//      ever credits THIS cell, never the relayer -- this kills relay/credit theft.
//    - The nonce is fresh each sweep, so recorded answers cannot be replayed.
// ============================================================

let CHANNEL = 7
let CELL = 1
let TXPOWER = 2

// Same 128-bit pre-shared key as the sender (agreed in person, ideally loaded out-of-band).
let CELLKEY = [0x8f, 0x21, 0x6c, 0xa3, 0x0b, 0xd4, 0x77, 0x19, 0xe2, 0x55, 0x3a, 0x90, 0xc1, 0x4e, 0x88, 0x02]

let DAYKEY: number[] = []
let haveKey = false

// seed reassembly state
let seedIV: number[] = []
let seedC: number[] = []
let seedTag: number[] = []
let gotP1 = false
let gotP2 = false

radio.setGroup(CHANNEL)
radio.setTransmitPower(TXPOWER)
radio.setTransmitSerialNumber(true)   // so the Checker can bind our serial into the proof
basic.showString("R")

function ensureC(): void {
    if (seedC.length < 16) { seedC = []; for (let i = 0; i < 16; i++) seedC.push(0) }
}

function tryDecrypt(): void {
    if (!(gotP1 && gotP2)) return
    // verify tag = HMAC(CELLKEY, 0x01 || IV || C)[0..7]
    let tagIn: number[] = [0x01]
    for (let i = 0; i < 8; i++) tagIn.push(seedIV[i])
    for (let i = 0; i < 16; i++) tagIn.push(seedC[i])
    let t = take(hmac(CELLKEY, tagIn), 8)
    let ok = true
    for (let i = 0; i < 8; i++) if (t[i] != seedTag[i]) ok = false
    if (!ok) { basic.showIcon(IconNames.No); return }   // forged / tampered seed -> reject

    // decrypt: DAYKEY = C XOR HMAC(CELLKEY, 0x00 || IV)[0..15]
    let ksIn: number[] = [0x00]
    for (let i = 0; i < 8; i++) ksIn.push(seedIV[i])
    let ks = hmac(CELLKEY, ksIn)
    DAYKEY = []
    for (let i = 0; i < 16; i++) DAYKEY.push(seedC[i] ^ ks[i])
    haveKey = true
    basic.showIcon(IconNames.Yes)                       // "I hold today's key"
}

radio.onReceivedBuffer(function (buf: Buffer) {
    let type = buf.getUint8(0)
    let cell = buf.getUint8(1)
    if (cell != CELL) return                            // ignore other cells' traffic

    if (type == 1) {                                    // SEED part 1: IV + C[0..7]
        seedIV = []
        for (let i = 0; i < 8; i++) seedIV.push(buf.getUint8(2 + i))
        ensureC()
        for (let i = 0; i < 8; i++) seedC[i] = buf.getUint8(10 + i)
        gotP1 = true
        tryDecrypt()
    } else if (type == 2) {                             // SEED part 2: C[8..15] + tag
        ensureC()
        for (let i = 0; i < 8; i++) seedC[8 + i] = buf.getUint8(2 + i)
        seedTag = []
        for (let i = 0; i < 8; i++) seedTag.push(buf.getUint8(10 + i))
        gotP2 = true
        tryDecrypt()
    } else if (type == 3) {                             // CHALLENGE: 12-byte nonce
        if (!haveKey) return
        let dev = control.deviceSerialNumber()
        let macIn: number[] = [0x02]
        for (let i = 0; i < 12; i++) macIn.push(buf.getUint8(2 + i))    // nonce
        let sb = u32bytes(dev)
        for (let i = 0; i < 4; i++) macIn.push(sb[i])                    // our serial
        let mac = take(hmac(DAYKEY, macIn), 12)

        let resp = pins.createBuffer(14)                // [4][cell][mac 12]
        resp.setUint8(0, 4); resp.setUint8(1, CELL)
        for (let i = 0; i < 12; i++) resp.setUint8(2 + i, mac[i])
        radio.sendBuffer(resp)
        basic.showIcon(IconNames.SmallDiamond)
    }
})
