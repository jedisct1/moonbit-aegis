# AEGIS implementation in Moonbit

An implementation of the AEGIS authenticated encryption algorithms (AEGIS-128L and AEGIS-256) in the Moonbit language.

Both ciphers follow the [AEGIS specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) and are checked against its test vectors. Tags can be 16 or 32 bytes long.

## Usage

Add `jedisct1/aegis/lib` to the `import` list of your package, then:

```moonbit
let key = Bytes::make(16, b'\x01') // 32 bytes for AEGIS-256
let nonce = Bytes::make(16, b'\x02') // 32 bytes for AEGIS-256
let msg = b"hello"
let ad = b"header"

let ac = @lib.Aegis128L::new(key, nonce, 32).encrypt_detached(Some(msg), Some(ad))
// ac.ciphertext and ac.tag

let decrypted = @lib.Aegis128L::new(key, nonce, 32).decrypt_detached(ac, Some(ad))
```

A state object can only be used for one operation. `decrypt_detached` raises an error if the tag doesn't verify, and no plaintext is returned in that case.

## Tests and benchmarks

```sh
moon test --target all
moon bench --release --target native   # or js, wasm-gc
```

The benchmarks encrypt and decrypt 16 KB messages, and measure a full encryption of a short associated data string with no message.
