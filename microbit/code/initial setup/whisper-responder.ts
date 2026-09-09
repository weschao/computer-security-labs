// ============================================================
//  WHISPER NETWORK  ·  Program 2 of 2:  NONCE-CHALLENGE RESPONDER
//  ----------------------------------------------------------
//  Runs on every student device. It does two things:
//   (a) stores its cell's key when the Sender broadcasts it, and
//   (b) proves it knows the key when the instructor's Checker
//       sweeps with a (cell, nonce) challenge.
//
//  The key is saved to FLASH (the settings API), so it survives a
//  power loss or reset -- on boot the device reloads it automatically.
//
//  The proof function here is a TOY -- intentionally weak.
//  Breaking it and replacing it with a real MAC is the exercise.
//
//  HOW TO USE:  paste into makecode.microbit.org (JavaScript
//  view), flip to Blocks to edit, download .hex. Set CELL per
//  device before you flash it.
// ============================================================

let CHANNEL = 7      // same shared channel as everyone else
let CELL = 1         // this device's team id -- change per team
let STORE = "wnKey" + CELL   // name of the flash slot that holds our key
let KEY = 0          // filled in when we hear our cell's key (or restored from flash)
let haveKey = false

radio.setGroup(CHANNEL)
radio.setTransmitPower(7)
radio.setTransmitSerialNumber(true)   // so the Checker can see WHICH device answered

// On power-up, restore the key from flash if we saved one earlier.
// settings.* is the micro:bit's built-in non-volatile key/value store
// (flash-backed), so the value persists across power loss and resets.
if (settings.exists(STORE)) {
    KEY = settings.readNumber(STORE)
    haveKey = true
    basic.showIcon(IconNames.Yes)     // key survived the reboot -- ready
} else {
    basic.showString("R")             // ready, but no key yet
}

radio.onReceivedValue(function (name, value) {
    if (name == "key" + CELL) {
        // Our cell's key just arrived. Keep it in RAM AND write it to flash
        // so it survives a power loss. Skip the write when it's unchanged
        // (the Sender repeats the key several times) to spare flash wear.
        if (!(haveKey && value == KEY)) {
            KEY = value
            haveKey = true
            settings.writeNumber(STORE, value)    // persist across power loss
            basic.showIcon(IconNames.Yes)         // "I hold today's key"
        }
    } else if (name == "chal" + CELL) {
        // The Checker is challenging our cell with a fresh nonce.
        if (haveKey) {
            let nonce = value
            let response = (KEY + nonce) % 1000000   // <-- TOY PROOF. Weak on purpose.
            radio.sendValue("resp" + CELL, response)
            basic.showIcon(IconNames.SmallDiamond)   // answered
        }
    }
})
