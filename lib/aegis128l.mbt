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
  let key_block = AesBlock::from_bytes(key)
  let nonce_block = AesBlock::from_bytes(nonce)
  let kn = key_block.xor(nonce_block)
  //
  let s : FixedArray[AesBlock] = [
    kn,
    c1,
    c0,
    c1,
    kn,
    key_block.xor(c0),
    key_block.xor(c1),
    key_block.xor(c0),
  ]
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
fn Aegis128L::keystream(self : Aegis128L) -> (AesBlock, AesBlock) {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].land(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].land(s[7]))
  (z0, z1)
}

///|
/// Encrypts the plaintext block `t0 || t1` into `out[offset:offset + 32]`.
fn Aegis128L::enc(
  self : Aegis128L,
  t0 : AesBlock,
  t1 : AesBlock,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let (z0, z1) = self.keystream()
  self.update(t0, t1)
  t0.xor(z0).store(out, offset)
  t1.xor(z1).store(out, offset + 16)
}

///|
/// Decrypts the ciphertext block `t0 || t1` into `out[offset:offset + 32]`.
fn Aegis128L::dec(
  self : Aegis128L,
  t0 : AesBlock,
  t1 : AesBlock,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let (z0, z1) = self.keystream()
  let out0 = t0.xor(z0)
  let out1 = t1.xor(z1)
  self.update(out0, out1)
  out0.store(out, offset)
  out1.store(out, offset + 16)
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
  let (z0, z1) = self.keystream()
  AesBlock::load(pad, 0).xor(z0).store(pad, 0)
  AesBlock::load(pad, 16).xor(z1).store(pad, 16)
  pad.fill(b'\x00', start=cn_length)
  self.update(AesBlock::load(pad, 0), AesBlock::load(pad, 16))
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
  let t = s[2].xor(length_block(ad_len_bytes, msg_len_bytes))
  for _ in 0..<7 {
    self.update(t, t)
  }
  let tag = FixedArray::make(self.tag_length, b'\x00')
  if self.tag_length == 16 {
    s[0]
    .xor(s[1])
    .xor(s[2])
    .xor(s[3])
    .xor(s[4])
    .xor(s[5])
    .xor(s[6])
    .store(tag, 0)
  } else {
    s[0].xor(s[1]).xor(s[2]).xor(s[3]).store(tag, 0)
    s[4].xor(s[5]).xor(s[6]).xor(s[7]).store(tag, 16)
  }
  Bytes::from_array(tag)
}

///|
fn Aegis128L::absorb_ad(self : Aegis128L, ad : Bytes?) -> Int {
  guard ad is Some(ad) else { return 0 }
  let mut i = 0
  while i + 32 <= ad.length() {
    self.update(AesBlock::load_bytes(ad, i), AesBlock::load_bytes(ad, i + 16))
    i = i + 32
  }
  if i < ad.length() {
    let pad = FixedArray::make(32, b'\x00')
    pad.blit_from_bytes(0, ad, i, ad.length() - i)
    self.update(AesBlock::load(pad, 0), AesBlock::load(pad, 16))
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
  let mut i = 0
  while i + 32 <= msg_length {
    let t0 = AesBlock::load_bytes(msg, i)
    let t1 = AesBlock::load_bytes(msg, i + 16)
    self.enc(t0, t1, ciphertext, i)
    i = i + 32
  }
  if i < msg_length {
    let pad = FixedArray::make(32, b'\x00')
    pad.blit_from_bytes(0, msg, i, msg_length - i)
    self.enc(AesBlock::load(pad, 0), AesBlock::load(pad, 16), pad, 0)
    pad.blit_to(ciphertext, len=msg_length - i, dst_offset=i)
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
  let mut i = 0
  while i + 32 <= msg_length {
    let t0 = AesBlock::load_bytes(ciphertext, i)
    let t1 = AesBlock::load_bytes(ciphertext, i + 16)
    self.dec(t0, t1, msg, i)
    i = i + 32
  }
  if i < msg_length {
    let pad = FixedArray::make(32, b'\x00')
    pad.blit_from_bytes(0, ciphertext, i, msg_length - i)
    self.dec_last(pad, msg_length - i)
    pad.blit_to(msg, len=msg_length - i, dst_offset=i)
  }
  let tag = self.mac(ad_length, msg_length)
  if !tags_equal(tag, ac.tag) {
    msg.fill(b'\x00')
    fail("Verification failed")
  }
  Bytes::from_array(msg)
}
