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
/// Encodes `len(ad) * 8` and `len(msg) * 8` as two little-endian 64-bit
/// integers, as required by the finalization step.
fn encode_lengths(ad_len_bytes : Int, msg_len_bytes : Int) -> FixedArray[Byte] {
  let bytes = FixedArray::make(16, b'\x00')
  let ad_len = ad_len_bytes.to_int64() * 8L
  let msg_len = msg_len_bytes.to_int64() * 8L
  for i = 0; i < 8; i = i + 1 {
    bytes[0 * 8 + i] = (ad_len >> (8 * i)).to_byte()
    bytes[1 * 8 + i] = (msg_len >> (8 * i)).to_byte()
  }
  bytes
}

///|
/// AEGIS constant C0 (Fibonacci sequence modulo 256).
let c0_bytes : FixedArray[Byte] = [
  b'\x00', b'\x01', b'\x01', b'\x02', b'\x03', b'\x05', b'\x08', b'\x0d', b'\x15',
  b'\x22', b'\x37', b'\x59', b'\x90', b'\xe9', b'\x79', b'\x62',
]

///|
/// AEGIS constant C1.
let c1_bytes : FixedArray[Byte] = [
  b'\xdb', b'\x3d', b'\x18', b'\x55', b'\x6d', b'\xc2', b'\x2f', b'\xf1', b'\x20',
  b'\x11', b'\x31', b'\x42', b'\x73', b'\xb5', b'\x28', b'\xdd',
]
