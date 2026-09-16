///|
pub struct Aegis256 {
  state : FixedArray[AesBlock]
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
  //
  let key_bytes = FixedArray::make(32, b'\x00')
  key_bytes.blit_from_bytes(0, key, 0, 32)
  let nonce_bytes = FixedArray::make(32, b'\x00')
  nonce_bytes.blit_from_bytes(0, nonce, 0, 32)
  //
  let c0 = AesBlock::load(c0_bytes, 0)
  let c1 = AesBlock::load(c1_bytes, 0)
  //
  let k0 = AesBlock::load(key_bytes, 0)
  let k1 = AesBlock::load(key_bytes, 16)
  let n0 = AesBlock::load(nonce_bytes, 0)
  let n1 = AesBlock::load(nonce_bytes, 16)
  let k0n0 = k0.xor(n0)
  let k1n1 = k1.xor(n1)
  //
  let s = FixedArray::make(6, (Default::default() : AesBlock))
  s[0] = k0n0
  s[1] = k1n1
  s[2] = c1
  s[3] = c0
  s[4] = k0.xor(c0)
  s[5] = k1.xor(c1)
  let self : Aegis256 = { tag_length, state: s, finalized: false, }
  //
  for _ in 0..<4 {
    self.update(k0)
    self.update(k1)
    self.update(k0n0)
    self.update(k1n1)
  }
  //
  self
}

///|
fn Aegis256::update(self : Aegis256, m : AesBlock) -> Unit {
  let s = self.state
  let tmp = s[5]
  s[5] = s[4].encrypt(s[5])
  s[4] = s[3].encrypt(s[4])
  s[3] = s[2].encrypt(s[3])
  s[2] = s[1].encrypt(s[2])
  s[1] = s[0].encrypt(s[1])
  s[0] = tmp.encrypt(s[0])
  s[0] = s[0].xor(m)
}

///|
fn Aegis256::absorb(self : Aegis256, ai : FixedArray[Byte]) -> Unit {
  let t = AesBlock::load(ai, 0)
  self.update(t)
}

///|
/// Encrypts the 16-byte block `xi` in place.
fn Aegis256::enc(self : Aegis256, xi : FixedArray[Byte]) -> Unit {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].land(s[3]))
  let t = AesBlock::load(xi, 0)
  let ci = t.xor(z)
  self.update(t)
  ci.store(xi, 0)
}

///|
/// Decrypts the 16-byte block `ci` in place.
fn Aegis256::dec(self : Aegis256, ci : FixedArray[Byte]) -> Unit {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].land(s[3]))
  let t = AesBlock::load(ci, 0)
  let xi = t.xor(z)
  self.update(xi)
  xi.store(ci, 0)
}

///|
/// Decrypts the final partial block. `pad` holds the `cn_length` ciphertext
/// bytes followed by zeros; on return, its first `cn_length` bytes hold the
/// plaintext.
fn Aegis256::dec_last(
  self : Aegis256,
  pad : FixedArray[Byte],
  cn_length : Int,
) -> Unit {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].land(s[3]))
  let t = AesBlock::load(pad, 0)
  t.xor(z).store(pad, 0)
  for i = cn_length; i < 16; i = i + 1 {
    pad[i] = b'\x00'
  }
  let v = AesBlock::load(pad, 0)
  self.update(v)
}

///|
fn Aegis256::mac(
  self : Aegis256,
  ad_len_bytes : Int,
  msg_len_bytes : Int,
) -> Bytes {
  self.finalized = true
  //
  let s = self.state
  let t = s[3].xor(
    AesBlock::load(encode_lengths(ad_len_bytes, msg_len_bytes), 0),
  )
  for _ in 0..<7 {
    self.update(t)
  }
  if self.tag_length == 16 {
    return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).to_bytes()
  }
  let tag = FixedArray::make(32, b'\x00')
  s[0].xor(s[1]).xor(s[2]).store(tag, 0)
  s[3].xor(s[4]).xor(s[5]).store(tag, 16)
  Bytes::from_array(tag)
}

///|
fn Aegis256::absorb_ad(self : Aegis256, ad : Bytes?) -> Int {
  guard ad is Some(ad) else { return 0 }
  let buf16 = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i + 16 <= ad.length() {
    buf16.blit_from_bytes(0, ad, i, 16)
    self.absorb(buf16)
    i = i + 16
  }
  if ad.length() % 16 != 0 {
    buf16.fill(b'\x00')
    buf16.blit_from_bytes(0, ad, i, ad.length() % 16)
    self.absorb(buf16)
  }
  ad.length()
}

///|
pub fn Aegis256::encrypt_detached(
  self : Aegis256,
  msg : Bytes?,
  ad : Bytes?,
) -> AuthenticatedCiphertext raise {
  assert_true(!self.finalized)
  //
  let ad_length = self.absorb_ad(ad)
  let msg = msg.unwrap_or(b"")
  let msg_length = msg.length()
  let ciphertext = FixedArray::make(msg_length, b'\x00')
  let buf16 = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i + 16 <= msg_length {
    buf16.blit_from_bytes(0, msg, i, 16)
    self.enc(buf16)
    buf16.blit_to(ciphertext, len=16, dst_offset=i)
    i = i + 16
  }
  if msg_length % 16 != 0 {
    buf16.fill(b'\x00')
    buf16.blit_from_bytes(0, msg, i, msg_length % 16)
    self.enc(buf16)
    buf16.blit_to(ciphertext, len=msg_length % 16, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  { ciphertext: Bytes::from_array(ciphertext), tag, }
}

///|
pub fn Aegis256::decrypt_detached(
  self : Aegis256,
  ac : AuthenticatedCiphertext,
  ad : Bytes?,
) -> Bytes raise {
  assert_true(!self.finalized)
  //
  let ad_length = self.absorb_ad(ad)
  let ciphertext = ac.ciphertext
  let msg_length = ciphertext.length()
  let msg = FixedArray::make(msg_length, b'\x00')
  let buf16 = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i + 16 <= msg_length {
    buf16.blit_from_bytes(0, ciphertext, i, 16)
    self.dec(buf16)
    buf16.blit_to(msg, len=16, dst_offset=i)
    i = i + 16
  }
  if msg_length % 16 != 0 {
    buf16.fill(b'\x00')
    buf16.blit_from_bytes(0, ciphertext, i, msg_length % 16)
    self.dec_last(buf16, msg_length % 16)
    buf16.blit_to(msg, len=msg_length % 16, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  if !tags_equal(tag, ac.tag) {
    msg.fill(b'\x00')
    fail("Verification failed")
  }
  Bytes::from_array(msg)
}
