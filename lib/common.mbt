///|
pub(all) struct AuthenticatedCiphertext {
  ciphertext : Bytes
  tag : Bytes
}

///|
/// Constant-time comparison of two tags.
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
/// The block `LE64(ad_len_bits) || LE64(msg_len_bits)` absorbed during
/// finalization.
fn length_block(ad_len_bytes : Int, msg_len_bytes : Int) -> AesBlock {
  let ad_len = ad_len_bytes.to_int64() * 8L
  let msg_len = msg_len_bytes.to_int64() * 8L
  {
    a: ad_len.to_int(),
    b: (ad_len >> 32).to_int(),
    c: msg_len.to_int(),
    d: (msg_len >> 32).to_int(),
  }
}

///|
/// AEGIS constant C0 (00 01 01 02 03 05 08 0d 15 22 37 59 90 e9 79 62),
/// loaded as little-endian words.
let c0 : AesBlock = {
  a: 0x02010100,
  b: 0x0d080503,
  c: 0x59372215,
  d: 0x6279e990,
}

///|
/// AEGIS constant C1 (db 3d 18 55 6d c2 2f f1 20 11 31 42 73 b5 28 dd),
/// loaded as little-endian words.
let c1 : AesBlock = {
  a: 0x55183ddb,
  b: 0xf12fc26d,
  c: 0x42311120,
  d: 0xdd28b573,
}
