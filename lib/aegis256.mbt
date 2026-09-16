///|
/// The state is a flat list of 32-bit words.
/// The six state blocks come first, followed by the message block that `update` mixes in.
const S256_M : Int = 24

///|
const S256_WORDS : Int = 28

///|
pub struct Aegis256 {
  state : FixedArray[Int]
  tag_length : Int
  mut finalized : Bool
} derive(Debug)

///|
pub fn Aegis256::new(
  key : Bytes,
  nonce : Bytes,
  tag_length : Int,
) -> Aegis256 raise {
  assert_true(key.length() == 32)
  assert_true(nonce.length() == 32)
  assert_true(tag_length == 16 || tag_length == 32)
  let st = words_from(FixedArray::make(S256_WORDS, 0))
  // Setup keeps mixing in these four blocks, built from the key and the nonce
  let init_blocks = FixedArray::make(16, 0)
  for j in 0..<4 {
    let k0 = load_le32_bytes(key, 4 * j)
    let k1 = load_le32_bytes(key, 16 + 4 * j)
    let n0 = load_le32_bytes(nonce, 4 * j)
    let n1 = load_le32_bytes(nonce, 16 + 4 * j)
    st[0 + j] = k0 ^ n0
    st[4 + j] = k1 ^ n1
    st[8 + j] = c1[j]
    st[12 + j] = c0[j]
    st[16 + j] = k0 ^ c0[j]
    st[20 + j] = k1 ^ c1[j]
    init_blocks[0 + j] = k0
    init_blocks[4 + j] = k1
    init_blocks[8 + j] = k0 ^ n0
    init_blocks[12 + j] = k1 ^ n1
  }
  let self : Aegis256 = { tag_length, state: st, finalized: false, }
  for _ in 0..<4 {
    for b in 0..<4 {
      init_blocks.blit_to(st, len=4, src_offset=4 * b, dst_offset=S256_M)
      self.update()
    }
  }
  self
}

///|
/// Scrambles the state and mixes in the message block.
/// Everything is read before anything is written, so every round starts from the old state.
fn Aegis256::update(self : Aegis256) -> Unit {
  let st = self.state
  let s00 = st.unsafe_get(0)
  let s01 = st.unsafe_get(1)
  let s02 = st.unsafe_get(2)
  let s03 = st.unsafe_get(3)
  let s10 = st.unsafe_get(4)
  let s11 = st.unsafe_get(5)
  let s12 = st.unsafe_get(6)
  let s13 = st.unsafe_get(7)
  let s20 = st.unsafe_get(8)
  let s21 = st.unsafe_get(9)
  let s22 = st.unsafe_get(10)
  let s23 = st.unsafe_get(11)
  let s30 = st.unsafe_get(12)
  let s31 = st.unsafe_get(13)
  let s32 = st.unsafe_get(14)
  let s33 = st.unsafe_get(15)
  let s40 = st.unsafe_get(16)
  let s41 = st.unsafe_get(17)
  let s42 = st.unsafe_get(18)
  let s43 = st.unsafe_get(19)
  let s50 = st.unsafe_get(20)
  let s51 = st.unsafe_get(21)
  let s52 = st.unsafe_get(22)
  let s53 = st.unsafe_get(23)
  st.unsafe_set(
    0,
    lut_get(lut0, s50) ^
    lut_get(lut1, s51 >> 8) ^
    lut_get(lut2, s52 >> 16) ^
    lut_get(lut3, s53 >> 24) ^
    s00 ^
    st.unsafe_get(S256_M),
  )
  st.unsafe_set(
    1,
    lut_get(lut0, s51) ^
    lut_get(lut1, s52 >> 8) ^
    lut_get(lut2, s53 >> 16) ^
    lut_get(lut3, s50 >> 24) ^
    s01 ^
    st.unsafe_get(S256_M + 1),
  )
  st.unsafe_set(
    2,
    lut_get(lut0, s52) ^
    lut_get(lut1, s53 >> 8) ^
    lut_get(lut2, s50 >> 16) ^
    lut_get(lut3, s51 >> 24) ^
    s02 ^
    st.unsafe_get(S256_M + 2),
  )
  st.unsafe_set(
    3,
    lut_get(lut0, s53) ^
    lut_get(lut1, s50 >> 8) ^
    lut_get(lut2, s51 >> 16) ^
    lut_get(lut3, s52 >> 24) ^
    s03 ^
    st.unsafe_get(S256_M + 3),
  )
  st.unsafe_set(
    4,
    lut_get(lut0, s00) ^
    lut_get(lut1, s01 >> 8) ^
    lut_get(lut2, s02 >> 16) ^
    lut_get(lut3, s03 >> 24) ^
    s10,
  )
  st.unsafe_set(
    5,
    lut_get(lut0, s01) ^
    lut_get(lut1, s02 >> 8) ^
    lut_get(lut2, s03 >> 16) ^
    lut_get(lut3, s00 >> 24) ^
    s11,
  )
  st.unsafe_set(
    6,
    lut_get(lut0, s02) ^
    lut_get(lut1, s03 >> 8) ^
    lut_get(lut2, s00 >> 16) ^
    lut_get(lut3, s01 >> 24) ^
    s12,
  )
  st.unsafe_set(
    7,
    lut_get(lut0, s03) ^
    lut_get(lut1, s00 >> 8) ^
    lut_get(lut2, s01 >> 16) ^
    lut_get(lut3, s02 >> 24) ^
    s13,
  )
  st.unsafe_set(
    8,
    lut_get(lut0, s10) ^
    lut_get(lut1, s11 >> 8) ^
    lut_get(lut2, s12 >> 16) ^
    lut_get(lut3, s13 >> 24) ^
    s20,
  )
  st.unsafe_set(
    9,
    lut_get(lut0, s11) ^
    lut_get(lut1, s12 >> 8) ^
    lut_get(lut2, s13 >> 16) ^
    lut_get(lut3, s10 >> 24) ^
    s21,
  )
  st.unsafe_set(
    10,
    lut_get(lut0, s12) ^
    lut_get(lut1, s13 >> 8) ^
    lut_get(lut2, s10 >> 16) ^
    lut_get(lut3, s11 >> 24) ^
    s22,
  )
  st.unsafe_set(
    11,
    lut_get(lut0, s13) ^
    lut_get(lut1, s10 >> 8) ^
    lut_get(lut2, s11 >> 16) ^
    lut_get(lut3, s12 >> 24) ^
    s23,
  )
  st.unsafe_set(
    12,
    lut_get(lut0, s20) ^
    lut_get(lut1, s21 >> 8) ^
    lut_get(lut2, s22 >> 16) ^
    lut_get(lut3, s23 >> 24) ^
    s30,
  )
  st.unsafe_set(
    13,
    lut_get(lut0, s21) ^
    lut_get(lut1, s22 >> 8) ^
    lut_get(lut2, s23 >> 16) ^
    lut_get(lut3, s20 >> 24) ^
    s31,
  )
  st.unsafe_set(
    14,
    lut_get(lut0, s22) ^
    lut_get(lut1, s23 >> 8) ^
    lut_get(lut2, s20 >> 16) ^
    lut_get(lut3, s21 >> 24) ^
    s32,
  )
  st.unsafe_set(
    15,
    lut_get(lut0, s23) ^
    lut_get(lut1, s20 >> 8) ^
    lut_get(lut2, s21 >> 16) ^
    lut_get(lut3, s22 >> 24) ^
    s33,
  )
  st.unsafe_set(
    16,
    lut_get(lut0, s30) ^
    lut_get(lut1, s31 >> 8) ^
    lut_get(lut2, s32 >> 16) ^
    lut_get(lut3, s33 >> 24) ^
    s40,
  )
  st.unsafe_set(
    17,
    lut_get(lut0, s31) ^
    lut_get(lut1, s32 >> 8) ^
    lut_get(lut2, s33 >> 16) ^
    lut_get(lut3, s30 >> 24) ^
    s41,
  )
  st.unsafe_set(
    18,
    lut_get(lut0, s32) ^
    lut_get(lut1, s33 >> 8) ^
    lut_get(lut2, s30 >> 16) ^
    lut_get(lut3, s31 >> 24) ^
    s42,
  )
  st.unsafe_set(
    19,
    lut_get(lut0, s33) ^
    lut_get(lut1, s30 >> 8) ^
    lut_get(lut2, s31 >> 16) ^
    lut_get(lut3, s32 >> 24) ^
    s43,
  )
  st.unsafe_set(
    20,
    lut_get(lut0, s40) ^
    lut_get(lut1, s41 >> 8) ^
    lut_get(lut2, s42 >> 16) ^
    lut_get(lut3, s43 >> 24) ^
    s50,
  )
  st.unsafe_set(
    21,
    lut_get(lut0, s41) ^
    lut_get(lut1, s42 >> 8) ^
    lut_get(lut2, s43 >> 16) ^
    lut_get(lut3, s40 >> 24) ^
    s51,
  )
  st.unsafe_set(
    22,
    lut_get(lut0, s42) ^
    lut_get(lut1, s43 >> 8) ^
    lut_get(lut2, s40 >> 16) ^
    lut_get(lut3, s41 >> 24) ^
    s52,
  )
  st.unsafe_set(
    23,
    lut_get(lut0, s43) ^
    lut_get(lut1, s40 >> 8) ^
    lut_get(lut2, s41 >> 16) ^
    lut_get(lut3, s42 >> 24) ^
    s53,
  )
}

///|
/// Mixes the 16 bytes of `src` starting at `offset` into the state.
/// The caller makes sure they're all there.
fn Aegis256::absorb(self : Aegis256, src : Bytes, offset : Int) -> Unit {
  let st = self.state
  for j in 0..<4 {
    st.unsafe_set(S256_M + j, load_le32_bytes(src, offset + 4 * j))
  }
  self.update()
}

///|
/// Encrypts the 16 bytes of `src` starting at `offset` into the same spot in `out`.
/// The caller makes sure both are long enough.
fn Aegis256::enc(
  self : Aegis256,
  src : Bytes,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let st = self.state
  for j in 0..<4 {
    // Keystream: z = S1 ^ S4 ^ S5 ^ (S2 & S3)
    let z = st.unsafe_get(4 + j) ^
      st.unsafe_get(16 + j) ^
      st.unsafe_get(20 + j) ^
      (st.unsafe_get(8 + j) & st.unsafe_get(12 + j))
    let xi = load_le32_bytes(src, offset + 4 * j)
    st.unsafe_set(S256_M + j, xi)
    store_le32(out, offset + 4 * j, xi ^ z)
  }
  self.update()
}

///|
/// Decrypts the 16 bytes of `src` starting at `offset` into the same spot in `out`.
/// The caller makes sure both are long enough.
fn Aegis256::dec(
  self : Aegis256,
  src : Bytes,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let st = self.state
  for j in 0..<4 {
    let z = st.unsafe_get(4 + j) ^
      st.unsafe_get(16 + j) ^
      st.unsafe_get(20 + j) ^
      (st.unsafe_get(8 + j) & st.unsafe_get(12 + j))
    let xi = load_le32_bytes(src, offset + 4 * j) ^ z
    st.unsafe_set(S256_M + j, xi)
    store_le32(out, offset + 4 * j, xi)
  }
  self.update()
}

///|
/// Decrypts the last, incomplete chunk in place.
/// `pad` starts with the leftover ciphertext followed by zeros, and ends up with the plaintext in the same spot.
fn Aegis256::dec_last(
  self : Aegis256,
  pad : FixedArray[Byte],
  cn_length : Int,
) -> Unit {
  let st = self.state
  for j in 0..<4 {
    let z = st[4 + j] ^ st[16 + j] ^ st[20 + j] ^ (st[8 + j] & st[12 + j])
    store_le32(pad, 4 * j, load_le32(pad, 4 * j) ^ z)
  }
  pad.fill(b'\x00', start=cn_length)
  for j in 0..<4 {
    st[S256_M + j] = load_le32(pad, 4 * j)
  }
  self.update()
}

///|
fn Aegis256::mac(
  self : Aegis256,
  ad_len_bytes : Int,
  msg_len_bytes : Int,
) -> Bytes {
  self.finalized = true
  let st = self.state
  // Mix in both lengths, combined with block 3, seven times over
  store_length_block(st, S256_M, ad_len_bytes, msg_len_bytes)
  for j in 0..<4 {
    st[S256_M + j] = st[S256_M + j] ^ st[12 + j]
  }
  for _ in 0..<7 {
    self.update()
  }
  let tag = FixedArray::make(self.tag_length, b'\x00')
  for j in 0..<4 {
    let t0 = st[0 + j] ^ st[4 + j] ^ st[8 + j]
    let t1 = st[12 + j] ^ st[16 + j] ^ st[20 + j]
    if self.tag_length == 16 {
      store_le32(tag, 4 * j, t0 ^ t1)
    } else {
      store_le32(tag, 4 * j, t0)
      store_le32(tag, 16 + 4 * j, t1)
    }
  }
  freeze(tag)
}

///|
fn Aegis256::absorb_ad(self : Aegis256, ad : Bytes?) -> Int {
  guard ad is Some(ad) else { return 0 }
  let ad_length = ad.length()
  let mut i = 0
  while i + 16 <= ad_length {
    self.absorb(ad, i)
    i = i + 16
  }
  if i < ad_length {
    let pad = FixedArray::make(16, b'\x00')
    pad.blit_from_bytes(0, ad, i, ad_length - i)
    self.absorb(Bytes::from_array(pad), 0)
  }
  ad_length
}

///|
pub fn Aegis256::encrypt_detached(
  self : Aegis256,
  msg : Bytes?,
  ad : Bytes?,
) -> AuthenticatedCiphertext raise {
  assert_true(!self.finalized)
  let ad_length = self.absorb_ad(ad)
  let msg = msg.unwrap_or(b"")
  let msg_length = msg.length()
  let ciphertext = FixedArray::make(msg_length, b'\x00')
  let mut i = 0
  while i + 16 <= msg_length {
    self.enc(msg, ciphertext, i)
    i = i + 16
  }
  if i < msg_length {
    let pad = FixedArray::make(16, b'\x00')
    pad.blit_from_bytes(0, msg, i, msg_length - i)
    self.enc(Bytes::from_array(pad), pad, 0)
    pad.blit_to(ciphertext, len=msg_length - i, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  { ciphertext: freeze(ciphertext), tag, }
}

///|
pub fn Aegis256::decrypt_detached(
  self : Aegis256,
  ac : AuthenticatedCiphertext,
  ad : Bytes?,
) -> Bytes raise {
  assert_true(!self.finalized)
  let ad_length = self.absorb_ad(ad)
  let ciphertext = ac.ciphertext
  let msg_length = ciphertext.length()
  let msg = FixedArray::make(msg_length, b'\x00')
  let mut i = 0
  while i + 16 <= msg_length {
    self.dec(ciphertext, msg, i)
    i = i + 16
  }
  if i < msg_length {
    let pad = FixedArray::make(16, b'\x00')
    pad.blit_from_bytes(0, ciphertext, i, msg_length - i)
    self.dec_last(pad, msg_length - i)
    pad.blit_to(msg, len=msg_length - i, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  if !tags_equal(tag, ac.tag) {
    msg.fill(b'\x00')
    fail("Verification failed")
  }
  freeze(msg)
}
