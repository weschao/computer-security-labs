// ============================================================
//  WHISPER NETWORK  ·  COMPANION:  CHECKER  (the instructor's sweep)
//  ----------------------------------------------------------
//  Not part of the student assignment, but you need it to run
//  the end-of-class sweep and score responses.
//    A  = challenge the current cell with a fresh nonce
//    B  = move on to the next cell
//  Plug the Checker into a computer and open the MakeCode serial
//  console to see which device answered (for the +5 scoring).
// ============================================================

let CHANNEL = 7
// The instructor's private copy of each cell's key. Index = cell id; [0] is unused.
let cellKeys = [0, 482913, 771002, 155630]

radio.setGroup(CHANNEL)
radio.setTransmitPower(7)

let currentCell = 1
let nonce = 0
let expected = 0

input.onButtonPressed(Button.A, function () {
    nonce = Math.randomRange(100000, 999999)              // fresh nonce (note: weak RNG!)
    expected = (cellKeys[currentCell] + nonce) % 1000000  // what a correct proof should be
    radio.sendValue("chal" + currentCell, nonce)
    basic.showNumber(currentCell)
})

input.onButtonPressed(Button.B, function () {
    currentCell = currentCell + 1                          // sweep to the next cell
    basic.showNumber(currentCell)
})

radio.onReceivedValue(function (name, value) {
    if (name == "resp" + currentCell) {
        let who = radio.receivedPacket(RadioPacketProperty.SerialNumber)
        if (value == expected) {
            basic.showIcon(IconNames.Yes)     // correct proof
        } else {
            basic.showIcon(IconNames.No)      // wrong proof
        }
        // Log the answering device's serial + whether it was correct, for scoring.
        // If 'who' belongs to another cell, that cell earns +5.
        serial.writeValue("device", who)
        serial.writeValue("correct", value == expected ? 1 : 0)
    }
})
