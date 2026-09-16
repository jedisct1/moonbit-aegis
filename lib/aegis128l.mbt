///|
pub struct Aegis128L {
  state : FixedArray[AesBlock]
  tag_length : Int
  mut finalized : Bool
} derive(Debug)

///|
pub fn Aegis128L::new(
  key : Bytes,
  nonce : Bytes,
  tag_length : Int,
) -> Aegis128L raise {
  assert_true(key.length() == 16)
  assert_true(nonce.length() == 16)
  assert_true(tag_length == 16 || tag_length == 32)
  //
  let c0 = AesBlock::load(c0_bytes, 0)
  let c1 = AesBlock::load(c1_bytes, 0)
  //
  let key_block = AesBlock::from_bytes(key)
  let nonce_block = AesBlock::from_bytes(nonce)
  //
  let s = FixedArray::make(8, (Default::default() : AesBlock))
  s[0] = key_block.xor(nonce_block)
  s[1] = c1
  s[2] = c0
  s[3] = c1
  s[4] = key_block.xor(nonce_block)
  s[5] = key_block.xor(c0)
  s[6] = key_block.xor(c1)
  s[7] = key_block.xor(c0)
  let self : Aegis128L = { tag_length, state: s, finalized: false, }
  //
  for _ in 0..<10 {
    self.update(nonce_block, key_block)
  }
  //
  self
}

///|
fn Aegis128L::update(self : Aegis128L, m0 : AesBlock, m1 : AesBlock) -> Unit {
  let s = self.state
  let tmp = s[7]
  s[7] = s[6].encrypt(s[7])
  s[6] = s[5].encrypt(s[6])
  s[5] = s[4].encrypt(s[5])
  s[4] = s[3].encrypt(s[4])
  s[3] = s[2].encrypt(s[3])
  s[2] = s[1].encrypt(s[2])
  s[1] = s[0].encrypt(s[1])
  s[0] = tmp.encrypt(s[0])
  s[4] = s[4].xor(m1)
  s[0] = s[0].xor(m0)
}

///|
fn Aegis128L::absorb(self : Aegis128L, ai : FixedArray[Byte]) -> Unit {
  let t0 = AesBlock::load(ai, 0)
  let t1 = AesBlock::load(ai, 16)
  self.update(t0, t1)
}

///|
/// Encrypts the 32-byte block `xi` in place.
fn Aegis128L::enc(self : Aegis128L, xi : FixedArray[Byte]) -> Unit {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].land(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].land(s[7]))
  let t0 = AesBlock::load(xi, 0)
  let t1 = AesBlock::load(xi, 16)
  let out0 = t0.xor(z0)
  let out1 = t1.xor(z1)
  self.update(t0, t1)
  out0.store(xi, 0)
  out1.store(xi, 16)
}

///|
/// Decrypts the 32-byte block `ci` in place.
fn Aegis128L::dec(self : Aegis128L, ci : FixedArray[Byte]) -> Unit {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].land(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].land(s[7]))
  let t0 = AesBlock::load(ci, 0)
  let t1 = AesBlock::load(ci, 16)
  let out0 = t0.xor(z0)
  let out1 = t1.xor(z1)
  self.update(out0, out1)
  out0.store(ci, 0)
  out1.store(ci, 16)
}

///|
/// Decrypts the final partial block. `pad` holds the `cn_length` ciphertext
/// bytes followed by zeros; on return, its first `cn_length` bytes hold the
/// plaintext.
fn Aegis128L::dec_last(
  self : Aegis128L,
  pad : FixedArray[Byte],
  cn_length : Int,
) -> Unit {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].land(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].land(s[7]))
  let t0 = AesBlock::load(pad, 0)
  let t1 = AesBlock::load(pad, 16)
  let out0 = t0.xor(z0)
  let out1 = t1.xor(z1)
  out0.store(pad, 0)
  out1.store(pad, 16)
  for i = cn_length; i < 32; i = i + 1 {
    pad[i] = b'\x00'
  }
  let v0 = AesBlock::load(pad, 0)
  let v1 = AesBlock::load(pad, 16)
  self.update(v0, v1)
}

///|
fn Aegis128L::mac(
  self : Aegis128L,
  ad_len_bytes : Int,
  msg_len_bytes : Int,
) -> Bytes {
  self.finalized = true
  //
  let s = self.state
  let t = s[2].xor(
    AesBlock::load(encode_lengths(ad_len_bytes, msg_len_bytes), 0),
  )
  for _ in 0..<7 {
    self.update(t, t)
  }
  if self.tag_length == 16 {
    return s[0]
      .xor(s[1])
      .xor(s[2])
      .xor(s[3])
      .xor(s[4])
      .xor(s[5])
      .xor(s[6])
      .to_bytes()
  }
  let tag = FixedArray::make(32, b'\x00')
  s[0].xor(s[1]).xor(s[2]).xor(s[3]).store(tag, 0)
  s[4].xor(s[5]).xor(s[6]).xor(s[7]).store(tag, 16)
  Bytes::from_array(tag)
}

///|
fn Aegis128L::absorb_ad(self : Aegis128L, ad : Bytes?) -> Int {
  guard ad is Some(ad) else { return 0 }
  let buf32 = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i + 32 <= ad.length() {
    buf32.blit_from_bytes(0, ad, i, 32)
    self.absorb(buf32)
    i = i + 32
  }
  if ad.length() % 32 != 0 {
    buf32.fill(b'\x00')
    buf32.blit_from_bytes(0, ad, i, ad.length() % 32)
    self.absorb(buf32)
  }
  ad.length()
}

///|
pub fn Aegis128L::encrypt_detached(
  self : Aegis128L,
  msg : Bytes?,
  ad : Bytes?,
) -> AuthenticatedCiphertext raise {
  assert_true(!self.finalized)
  //
  let ad_length = self.absorb_ad(ad)
  let msg = msg.unwrap_or(b"")
  let msg_length = msg.length()
  let ciphertext = FixedArray::make(msg_length, b'\x00')
  let buf32 = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i + 32 <= msg_length {
    buf32.blit_from_bytes(0, msg, i, 32)
    self.enc(buf32)
    buf32.blit_to(ciphertext, len=32, dst_offset=i)
    i = i + 32
  }
  if msg_length % 32 != 0 {
    buf32.fill(b'\x00')
    buf32.blit_from_bytes(0, msg, i, msg_length % 32)
    self.enc(buf32)
    buf32.blit_to(ciphertext, len=msg_length % 32, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  { ciphertext: Bytes::from_array(ciphertext), tag, }
}

///|
pub fn Aegis128L::decrypt_detached(
  self : Aegis128L,
  ac : AuthenticatedCiphertext,
  ad : Bytes?,
) -> Bytes raise {
  assert_true(!self.finalized)
  //
  let ad_length = self.absorb_ad(ad)
  let ciphertext = ac.ciphertext
  let msg_length = ciphertext.length()
  let msg = FixedArray::make(msg_length, b'\x00')
  let buf32 = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i + 32 <= msg_length {
    buf32.blit_from_bytes(0, ciphertext, i, 32)
    self.dec(buf32)
    buf32.blit_to(msg, len=32, dst_offset=i)
    i = i + 32
  }
  if msg_length % 32 != 0 {
    buf32.fill(b'\x00')
    buf32.blit_from_bytes(0, ciphertext, i, msg_length % 32)
    self.dec_last(buf32, msg_length % 32)
    buf32.blit_to(msg, len=msg_length % 32, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  if !tags_equal(tag, ac.tag) {
    msg.fill(b'\x00')
    fail("Verification failed")
  }
  Bytes::from_array(msg)
}
