///|
pub(all) struct AuthenticatedCiphertext {
  ciphertext : Bytes
  tag : Bytes
}

///|
/// Compares two tags without leaking, through timing, where they differ.
fn tags_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut dt = 0
  for i = 0; i < a.length(); i = i + 1 {
    dt = dt | (a[i].to_int() ^ b[i].to_int())
  }
  dt == 0
}

///|
/// Reads a little-endian 32-bit word.
/// The caller makes sure all four bytes are there.
#inline
fn load_le32_bytes(bytes : Bytes, offset : Int) -> Int {
  bytes.unsafe_get(offset).to_int() |
  (bytes.unsafe_get(offset + 1).to_int() << 8) |
  (bytes.unsafe_get(offset + 2).to_int() << 16) |
  (bytes.unsafe_get(offset + 3).to_int() << 24)
}

///|
/// Reads a little-endian 32-bit word.
/// The caller makes sure all four bytes are there.
#inline
fn load_le32(bytes : FixedArray[Byte], offset : Int) -> Int {
  bytes.unsafe_get(offset).to_int() |
  (bytes.unsafe_get(offset + 1).to_int() << 8) |
  (bytes.unsafe_get(offset + 2).to_int() << 16) |
  (bytes.unsafe_get(offset + 3).to_int() << 24)
}

///|
/// Writes a little-endian 32-bit word.
/// The caller makes sure there's room for it.
#inline
fn store_le32(bytes : FixedArray[Byte], offset : Int, x : Int) -> Unit {
  bytes.unsafe_set(offset, x.to_byte())
  bytes.unsafe_set(offset + 1, (x >> 8).to_byte())
  bytes.unsafe_set(offset + 2, (x >> 16).to_byte())
  bytes.unsafe_set(offset + 3, (x >> 24).to_byte())
}

///|
/// Writes the block that finishing up mixes in: the associated data length, then the message length, both in bits.
fn store_length_block(
  st : FixedArray[Int],
  offset : Int,
  ad_len_bytes : Int,
  msg_len_bytes : Int,
) -> Unit {
  let ad_len = ad_len_bytes.to_int64() * 8L
  let msg_len = msg_len_bytes.to_int64() * 8L
  st[offset] = ad_len.to_int()
  st[offset + 1] = (ad_len >> 32).to_int()
  st[offset + 2] = msg_len.to_int()
  st[offset + 3] = (msg_len >> 32).to_int()
}

///|
/// The AEGIS constant C0 (00 01 01 02 03 05 08 0d 15 22 37 59 90 e9 79 62), split into little-endian words.
let c0 : FixedArray[Int] = [0x02010100, 0x0d080503, 0x59372215, 0x6279e990]

///|
/// The AEGIS constant C1 (db 3d 18 55 6d c2 2f f1 20 11 31 42 73 b5 28 dd), split into little-endian words.
let c1 : FixedArray[Int] = [0x55183ddb, 0xf12fc26d, 0x42311120, 0xdd28b573]

///|
/// Hands over a finished output buffer as `Bytes` without copying it.
/// Nothing may write to the buffer after that.
fn freeze(buf : FixedArray[Byte]) -> Bytes {
  buf.unsafe_reinterpret_as_bytes()
}
