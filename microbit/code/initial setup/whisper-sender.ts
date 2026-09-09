// ============================================================
//  WHISPER NETWORK  ·  Program 1 of 2:  FULL-POWER SENDER
//  ----------------------------------------------------------
//  The deliberately-insecure DEFAULT. It broadcasts the day's
//  key at MAX power, in PLAINTEXT, on a channel the whole class
//  shares. Run it on the instructor's device to seed a cell, or
//  on a member's device to propagate the key to teammates.
//
//  HOW TO USE:  makecode.microbit.org  ->  New Project  ->
//  click the "{} JavaScript" toggle at top  ->  paste this in.
//  Flip back to "Blocks" to see/edit it visually. Download the
//  .hex to your micro:bit.
// ============================================================

let CHANNEL = 7      // radio group shared by the WHOLE class (the physical channel)
let CELL = 1         // this cell's team id (1, 2, 3, ...) -- change per team
let KEY = 482913     // the day's secret number. Instructor sets this before seeding.

radio.setGroup(CHANNEL)
radio.setTransmitPower(7)     // 7 = full power = maximum range = maximally leaky
basic.showString("S")         // "S" = Sender is ready

// Press A to broadcast the key to anyone listening on the channel.
input.onButtonPressed(Button.A, function () {
    for (let i = 0; i < 5; i++) {             // radio is lossy: repeat for reliability
        radio.sendValue("key" + CELL, KEY)    // e.g. name "key1", value = the key
        basic.pause(100)
    }
    basic.showIcon(IconNames.Yes)             // sent
})
