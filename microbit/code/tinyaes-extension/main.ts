// ============================================================
//  AES-128 SELF-TEST  (proves the extension works on real hardware)
//  Reproduces the FIPS-197 Appendix C.1 known-answer vector:
//     key        000102030405060708090a0b0c0d0e0f
//     plaintext  00112233445566778899aabbccddeeff
//     ciphertext 69c4e0d86a7b0430d8cdb78070b4c55a   <-- verified in Node
//  A checkmark = the on-device AES output matched the standard.
//  (The simulator can't run the C++ -- download to a micro:bit.)
// ============================================================

let key = pins.createBuffer(16)
for (let i = 0; i < 16; i++) key.setUint8(i, i)          // 00 01 .. 0f

let block = pins.createBuffer(16)
let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
for (let i = 0; i < 16; i++) block.setUint8(i, pt[i])

let expect = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]

tinyAES.ecbEncrypt(block, key)                           // encrypt in place

let okAll = true
for (let i = 0; i < 16; i++) {
    if (block.getUint8(i) != expect[i]) okAll = false
}

// round-trip decrypt should return the plaintext too
tinyAES.ecbDecrypt(block, key)
for (let i = 0; i < 16; i++) {
    if (block.getUint8(i) != pt[i]) okAll = false
}

basic.showIcon(okAll ? IconNames.Yes : IconNames.No)
