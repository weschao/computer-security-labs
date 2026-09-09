# tinyAES — AES-128 for micro:bit MakeCode

Wraps the public-domain [tiny-AES-c](https://github.com/kokke/tiny-AES-c) as a MakeCode
C++ extension so students call AES-128 from blocks/TypeScript. Symmetric crypto
(AES) runs natively on both micro:bit v1 (Cortex-M0) and v2 (Cortex-M4); tiny-AES-c
is ~1 KB of code and <200 bytes of RAM on ARM.

## Files you need

This folder provides three files:

- `pxt.json` — extension manifest
- `aes_shim.cpp` — the wrapper that exposes AES to MakeCode
- `main.ts` — a self-test that reproduces the FIPS-197 vector

You must add two more, straight from tiny-AES-c (public domain):

- `aes.h` — copy unchanged from the tiny-AES-c repo
- `aes.cpp` — copy `aes.c` from the repo and **rename it to `aes.cpp`**
  (it is plain C and compiles as C++; renaming lets MakeCode's C++ build pick it up)

tiny-AES-c defaults to **AES-128** with ECB/CBC/CTR enabled, so no edits to
`aes.h` are needed. (To force a mode set, define `ECB`/`CBC`/`CTR` and `AES128`.)

## Build & run

1. Put all five files (`pxt.json`, `aes.h`, `aes.cpp`, `aes_shim.cpp`, `main.ts`)
   in a public GitHub repo.
2. In makecode.microbit.org: **New Project → Extensions → paste the repo URL → import**.
   MakeCode's cloud compiler builds the C++ automatically.
3. **Download** the `.hex` to a micro:bit.
4. The LED grid shows a **checkmark** if the on-device AES output matched the
   standard vector (and decryption round-tripped), or an **✗** if not.

> The simulator cannot run the native C++ — test on real hardware.

## API

```typescript
tinyAES.ecbEncrypt(block, key)   // 16-byte block, 16-byte key, in place
tinyAES.ecbDecrypt(block, key)
tinyAES.ctrCrypt(buf, key, iv)   // any length, in place (encrypt == decrypt)
```

## Verification status

The AES-128 target ciphertext used by `main.ts`
(`69c4e0d86a7b0430d8cdb78070b4c55a`) was verified independently against
FIPS-197 in Node (see `verify_ciphers.js`). The wrapper follows the standard
PXT C++ `Buffer` conventions (`->data`, `->length`). The CODAL/C++ extension
itself must be compiled by MakeCode's build service — it cannot be built in a
plain Node environment — so run the self-test above to confirm on your board.

## Notes on the PXT C++ boundary

- `Buffer` in C++ is a PXT `BoxedBuffer*`; bytes are at `->data`, size at `->length`.
- Functions annotated with `//%` in a `namespace` are auto-exposed to TypeScript;
  MakeCode generates the shim during the cloud build.
- If your MakeCode/PXT version rejects `->data`, use the accessor `buf->data`
  equivalents from `pxt.h` for that version; the logic is unchanged.
