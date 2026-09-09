// ============================================================
//  WHISPER NETWORK · HARDENED CHECKER  (instructor's sweep)
//  >>> Paste the contents of whisper-crypto-lib.ts ABOVE this. <<<
//
//    A = challenge the current cell with a FRESH random nonce
//    B = advance to the next cell
//  For each response it reads the answering device's serial from the radio
//  frame, recomputes HMAC(cellKey, 0x02 || nonce || thatSerial), and checks it.
//  Open the MakeCode serial console: it logs (device serial, cell, correct?).
//  If a correct answer's serial belongs to a DIFFERENT cell -> that cell earns +5.
// ============================================================

let CHANNEL = 7

// The instructor's private copy of each cell's 128-bit DAY key. Index = cell id.
// cellKeys[0] is unused. Fill in each cell's key for the day.
let cellKeys = [
    [],
    [0xc7, 0x96, 0x63, 0x2a, 0x11, 0xff, 0x01, 0x58, 0x49, 0x40, 0x6f, 0xde, 0x21, 0xbe, 0x07, 0x80],  // cell 1
    [0x3d, 0x02, 0x9a, 0x71, 0x64, 0xc5, 0x18, 0xef, 0x00, 0xab, 0x5c, 0x37, 0x92, 0x10, 0xd8, 0x4b],  // cell 2
    [0x55, 0xe1, 0x20, 0x8c, 0x77, 0x39, 0xaa, 0x02, 0xbd, 0x6e, 0x14, 0xf0, 0x9c, 0x43, 0x81, 0x2f]   // cell 3
]

let currentCell = 1
let nonce: number[] = []

radio.setGroup(CHANNEL)
radio.setTransmitPower(2)
basic.showString("C")

function newNonce(): void {
    nonce = []
    for (let i = 0; i < 12; i++) nonce.push(Math.randomRange(0, 255))
}

input.onButtonPressed(Button.A, function () {
    newNonce()
    let p = pins.createBuffer(14)          // [3][cell][nonce 12]
    p.setUint8(0, 3); p.setUint8(1, currentCell)
    for (let i = 0; i < 12; i++) p.setUint8(2 + i, nonce[i])
    radio.sendBuffer(p)
    basic.showNumber(currentCell)
})

input.onButtonPressed(Button.B, function () {
    currentCell = currentCell + 1
    basic.showNumber(currentCell)
})

radio.onReceivedBuffer(function (buf: Buffer) {
    if (buf.getUint8(0) != 4) return                  // only responses
    let cell = buf.getUint8(1)
    if (cell >= cellKeys.length) return
    let key = cellKeys[cell]
    if (key.length < 16) return

    // the answering device's serial, straight from the radio frame (not payload-forgeable)
    let dev = radio.receivedPacket(RadioPacketProperty.SerialNumber)
    let macIn: number[] = [0x02]
    for (let i = 0; i < 12; i++) macIn.push(nonce[i])
    let sb = u32bytes(dev)
    for (let i = 0; i < 4; i++) macIn.push(sb[i])
    let mac = take(hmac(key, macIn), 12)

    let ok = true
    for (let i = 0; i < 12; i++) if (mac[i] != buf.getUint8(2 + i)) ok = false

    basic.showIcon(ok ? IconNames.Yes : IconNames.No)
    // Log for scoring. Map 'device' -> owning cell offline: same cell => +1, other cell => +5.
    serial.writeValue("device", dev)
    serial.writeValue("providedCell", cell)
    serial.writeValue("correct", ok ? 1 : 0)
})
