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
  let k0 = AesBlock::load_bytes(key, 0)
  let k1 = AesBlock::load_bytes(key, 16)
  let n0 = AesBlock::load_bytes(nonce, 0)
  let n1 = AesBlock::load_bytes(nonce, 16)
  let k0n0 = k0.xor(n0)
  let k1n1 = k1.xor(n1)
  //
  let s : FixedArray[AesBlock] = [k0n0, k1n1, c1, c0, k0.xor(c0), k1.xor(c1)]
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
fn Aegis256::keystream(self : Aegis256) -> AesBlock {
  let s = self.state
  s[1].xor(s[4]).xor(s[5]).xor(s[2].land(s[3]))
}

///|
/// Encrypts the plaintext block `t` into `out[offset:offset + 16]`.
fn Aegis256::enc(
  self : Aegis256,
  t : AesBlock,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let z = self.keystream()
  self.update(t)
  t.xor(z).store(out, offset)
}

///|
/// Decrypts the ciphertext block `t` into `out[offset:offset + 16]`.
fn Aegis256::dec(
  self : Aegis256,
  t : AesBlock,
  out : FixedArray[Byte],
  offset : Int,
) -> Unit {
  let xi = t.xor(self.keystream())
  self.update(xi)
  xi.store(out, offset)
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
  AesBlock::load(pad, 0).xor(self.keystream()).store(pad, 0)
  pad.fill(b'\x00', start=cn_length)
  self.update(AesBlock::load(pad, 0))
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
  let t = s[3].xor(length_block(ad_len_bytes, msg_len_bytes))
  for _ in 0..<7 {
    self.update(t)
  }
  let tag = FixedArray::make(self.tag_length, b'\x00')
  if self.tag_length == 16 {
    s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).store(tag, 0)
  } else {
    s[0].xor(s[1]).xor(s[2]).store(tag, 0)
    s[3].xor(s[4]).xor(s[5]).store(tag, 16)
  }
  Bytes::from_array(tag)
}

///|
fn Aegis256::absorb_ad(self : Aegis256, ad : Bytes?) -> Int {
  guard ad is Some(ad) else { return 0 }
  let mut i = 0
  while i + 16 <= ad.length() {
    self.update(AesBlock::load_bytes(ad, i))
    i = i + 16
  }
  if i < ad.length() {
    let pad = FixedArray::make(16, b'\x00')
    pad.blit_from_bytes(0, ad, i, ad.length() - i)
    self.update(AesBlock::load(pad, 0))
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
  let mut i = 0
  while i + 16 <= msg_length {
    self.enc(AesBlock::load_bytes(msg, i), ciphertext, i)
    i = i + 16
  }
  if i < msg_length {
    let pad = FixedArray::make(16, b'\x00')
    pad.blit_from_bytes(0, msg, i, msg_length - i)
    self.enc(AesBlock::load(pad, 0), pad, 0)
    pad.blit_to(ciphertext, len=msg_length - i, dst_offset=i)
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
  let mut i = 0
  while i + 16 <= msg_length {
    self.dec(AesBlock::load_bytes(ciphertext, i), msg, i)
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
  Bytes::from_array(msg)
}
