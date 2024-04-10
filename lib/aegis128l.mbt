pub struct Aegis128L {
  mut state : Array[AesBlock]
  mut tag_length : Int
  mut finalized : Bool
} derive(Debug, Show, Default)

pub fn Aegis128L::new(
  key : Bytes,
  nonce : Bytes,
  tag_length : Int
) -> Result[Aegis128L, String] {
  @assertion.assert_true(key.length() == 16)?
  @assertion.assert_true(nonce.length() == 16)?
  @assertion.assert_true(tag_length == 16 || tag_length == 32)?
  //
  let c0_bytes_int = [
    0x00,
    0x01,
    0x01,
    0x02,
    0x03,
    0x05,
    0x08,
    0x0d,
    0x15,
    0x22,
    0x37,
    0x59,
    0x90 - 256,
    0xe9 - 256,
    0x79,
    0x62,
  ]
  let c0_bytes = bytes_array_to_bytes(c0_bytes_int)
  //
  let c1_bytes_int = [
    0xdb - 256,
    0x3d,
    0x18,
    0x55,
    0x6d,
    0xc2 - 256,
    0x2f,
    0xf1 - 256,
    0x20,
    0x11,
    0x31,
    0x42,
    0x73,
    0xb5 - 256,
    0x28,
    0xdd - 256,
  ]
  let c1_bytes = bytes_array_to_bytes(c1_bytes_int)
  //
  let c0 = AesBlock::from_bytes(c0_bytes)
  let c1 = AesBlock::from_bytes(c1_bytes)
  //
  let key_block = AesBlock::from_bytes(key)
  let nonce_block = AesBlock::from_bytes(nonce)
  //  
  let s = Array::make(8, AesBlock::default())
  s[0] = key_block.xor(nonce_block)
  s[1] = c1
  s[2] = c0
  s[3] = c1
  s[4] = key_block.xor(nonce_block)
  s[5] = key_block.xor(c0)
  s[6] = key_block.xor(c1)
  s[7] = key_block.xor(c0)
  let self : Aegis128L = { tag_length, state: s, finalized: false }
  //
  for i = 0; i < 10; i = i + 1 {
    self.update(nonce_block, key_block)
  }
  //
  Ok(self)
}

fn update(self : Aegis128L, m0 : AesBlock, m1 : AesBlock) -> Unit {
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

fn absorb(self : Aegis128L, ai : Bytes) -> Unit {
  let ai0 = Bytes::make(16, 0)
  let ai1 = Bytes::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    ai0[i] = ai[i]
  }
  for i = 0; i < 16; i = i + 1 {
    ai1[i] = ai[i + 16]
  }
  let t0 = AesBlock::from_bytes(ai0)
  let t1 = AesBlock::from_bytes(ai1)
  self.update(t0, t1)
}

fn enc(self : Aegis128L, xi : Bytes) -> Bytes {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].and(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].and(s[7]))
  let xi0 = Bytes::make(16, 0)
  let xi1 = Bytes::make(16, 0)
  //
  for i = 0; i < 16; i = i + 1 {
    xi0[i] = xi[i]
  }
  for i = 0; i < 16; i = i + 1 {
    xi1[i] = xi[i + 16]
  }
  let t0 = AesBlock::from_bytes(xi0)
  let t1 = AesBlock::from_bytes(xi1)
  let out0_bytes = t0.xor(z0).to_bytes()
  let out1_bytes = t1.xor(z1).to_bytes()
  self.update(t0, t1)
  let ci = Bytes::make(32, 0)
  for i = 0; i < 16; i = i + 1 {
    ci[i] = out0_bytes[i]
  }
  for i = 0; i < 16; i = i + 1 {
    ci[i + 16] = out1_bytes[i]
  }
  return ci
}

fn dec(self : Aegis128L, ci : Bytes) -> Bytes {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].and(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].and(s[7]))
  let ci0 = Bytes::make(16, 0)
  let ci1 = Bytes::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    ci0[i] = ci[i]
  }
  for i = 0; i < 16; i = i + 1 {
    ci1[i] = ci[i + 16]
  }
  let t0 = AesBlock::from_bytes(ci0)
  let t1 = AesBlock::from_bytes(ci1)
  let out0 = t0.xor(z0)
  let out1 = t1.xor(z1)
  self.update(out0, out1)
  let out0_bytes = out0.to_bytes()
  let out1_bytes = out1.to_bytes()
  let xi = Bytes::make(32, 0)
  for i = 0; i < 16; i = i + 1 {
    xi[i] = out0_bytes[i]
  }
  for i = 0; i < 16; i = i + 1 {
    xi[i + 16] = out1_bytes[i]
  }
  xi
}

fn dec_last(self : Aegis128L, cn : Bytes) -> Bytes {
  let s = self.state
  let z0 = s[6].xor(s[1]).xor(s[2].and(s[3]))
  let z1 = s[2].xor(s[5]).xor(s[6].and(s[7]))
  let pad0 = Bytes::make(16, 0)
  let pad1 = Bytes::make(16, 0)
  let cn_length = cn.length()
  let n = if cn_length >= 16 { 16 } else { cn_length }
  for i = 0; i < n; i = i + 1 {
    pad0[i] = cn[i]
  }
  for i = 16; i < cn_length; i = i + 1 {
    pad1[i - 16] = cn[i]
  }
  let t0 = AesBlock::from_bytes(pad0)
  let t1 = AesBlock::from_bytes(pad1)
  let out0_bytes = t0.xor(z0).to_bytes()
  let out1_bytes = t1.xor(z1).to_bytes()
  for i = 0; i < 16; i = i + 1 {
    pad0[i] = out0_bytes[i]
  }
  for i = 0; i < 16; i = i + 1 {
    pad1[i] = out1_bytes[i]
  }
  let xn = Bytes::make(cn_length, 0)
  for i = 0; i < n; i = i + 1 {
    xn[i] = pad0[i]
  }
  for i = 16; i < cn_length; i = i + 1 {
    xn[i] = pad1[i - 16]
  }
  for i = cn_length; i < 16; i = i + 1 {
    pad0[i] = 0
  }
  if cn_length > 16 {
    for i = cn_length - 16; i < 16; i = i + 1 {
      pad1[i] = 0
    }
  }
  let v0 = AesBlock::from_bytes(pad0)
  let v1 = AesBlock::from_bytes(pad1)
  self.update(v0, v1)
  xn
}

fn mac(self : Aegis128L, ad_len_bytes : Int, msg_len_bytes : Int) -> Bytes {
  self.finalized = true
  //
  let s = self.state
  let bytes = Bytes::make(16, 0)
  //
  let ad_len = @int64.from_int(ad_len_bytes) * 8L
  let msg_len = @int64.from_int(msg_len_bytes) * 8L
  //
  bytes[0 * 8 + 0] = ad_len.lsr(0).to_int()
  bytes[0 * 8 + 1] = ad_len.lsr(8).to_int()
  bytes[0 * 8 + 2] = ad_len.lsr(16).to_int()
  bytes[0 * 8 + 3] = ad_len.lsr(24).to_int()
  bytes[0 * 8 + 4] = ad_len.lsr(32).to_int()
  bytes[0 * 8 + 5] = ad_len.lsr(40).to_int()
  bytes[0 * 8 + 6] = ad_len.lsr(48).to_int()
  bytes[0 * 8 + 7] = ad_len.lsr(56).to_int()
  bytes[1 * 8 + 0] = msg_len.lsr(0).to_int()
  bytes[1 * 8 + 1] = msg_len.lsr(8).to_int()
  bytes[1 * 8 + 2] = msg_len.lsr(16).to_int()
  bytes[1 * 8 + 3] = msg_len.lsr(24).to_int()
  bytes[1 * 8 + 4] = msg_len.lsr(32).to_int()
  bytes[1 * 8 + 5] = msg_len.lsr(40).to_int()
  bytes[1 * 8 + 6] = msg_len.lsr(48).to_int()
  bytes[1 * 8 + 7] = msg_len.lsr(56).to_int()
  //
  let t = s[2].xor(AesBlock::from_bytes(bytes))
  for i = 0; i < 7; i = i + 1 {
    self.update(t, t)
  }
  if self.tag_length == 16 {
    return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).xor(s[6]).to_bytes()
  }
  let tag = Bytes::make(32, 0)
  let t0 = s[0].xor(s[1]).xor(s[2]).xor(s[3]).to_bytes()
  let t1 = s[4].xor(s[5]).xor(s[6]).xor(s[7]).to_bytes()
  for i = 0; i < 16; i = i + 1 {
    tag[i] = t0[i]
  }
  for i = 0; i < 16; i = i + 1 {
    tag[16 + i] = t1[i]
  }
  tag
}

pub fn encrypt_detached(
  self : Aegis128L,
  msg : Option[Bytes],
  ad : Option[Bytes]
) -> AuthenticatedCiphertext {
  @assertion.assert_true(self.finalized.not()).unwrap()
  //  
  let buf32 = Bytes::make(32, 0)
  let mut i = 0
  if ad.is_empty().not() {
    let ad = ad.unwrap()
    while i + 32 <= ad.length() {
      for j = 0; j < 32; j = j + 1 {
        buf32[j] = ad[i + j]
      }
      self.absorb(buf32)
      i = i + 32
    }
    if ad.length() % 32 != 0 {
      let pad = buf32
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < ad.length() % 32; j = j + 1 {
        pad[i] = ad[i + j]
      }
      self.absorb(pad)
    }
  }
  let ciphertext_length = if msg.is_empty() { 0 } else { msg.unwrap().length() }
  let ciphertext = Bytes::make(ciphertext_length, 0)
  if msg.is_empty().not() {
    let msg = msg.unwrap()
    let mut i = 0
    while i + 32 <= msg.length() {
      for j = 0; j < 32; j = j + 1 {
        buf32[j] = msg[i + j]
      }
      let ci = self.enc(buf32)
      for j = 0; j < 32; j = j + 1 {
        ciphertext[i + j] = ci[j]
      }
      i = i + 32
    }
    if msg.length() % 32 != 0 {
      let pad = buf32
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < msg.length() % 32; j = j + 1 {
        pad[j] = msg[i + j]
      }
      let ci = self.enc(pad)
      for j = 0; j < msg.length() % 32; j = j + 1 {
        ciphertext[i + j] = ci[j]
      }
    }
  }
  let ad_length = if ad.is_empty() { 0 } else { ad.unwrap().length() }
  let msg_length = if msg.is_empty() { 0 } else { msg.unwrap().length() }
  let tag = self.mac(ad_length, msg_length)
  { ciphertext, tag }
}

pub fn decrypt_detached(
  self : Aegis128L,
  ac : AuthenticatedCiphertext,
  ad : Option[Bytes]
) -> Result[Bytes, String] {
  @assertion.assert_true(self.finalized.not()).unwrap()
  //  
  let buf32 = Bytes::make(32, 0)
  let mut i = 0
  if ad.is_empty().not() {
    let ad = ad.unwrap()
    while i + 32 <= ad.length() {
      for j = 0; j < 32; j = j + 1 {
        buf32[j] = ad[i + j]
      }
      self.absorb(buf32)
      i = i + 32
    }
    if ad.length() % 32 != 0 {
      let pad = buf32
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < ad.length() % 32; j = j + 1 {
        pad[i] = ad[i + j]
      }
      self.absorb(pad)
    }
  }
  let msg_length = ac.ciphertext.length()
  let msg = Bytes::make(msg_length, 0)
  let mut i = 0
  while i + 32 <= ac.ciphertext.length() {
    for j = 0; j < 32; j = j + 1 {
      buf32[j] = ac.ciphertext[i + j]
    }
    let xi = self.dec(buf32)
    for j = 0; j < 32; j = j + 1 {
      msg[i + j] = xi[j]
    }
    i = i + 32
  }
  if ac.ciphertext.length() % 32 != 0 {
    let remaining = Bytes::make(ac.ciphertext.length() % 32, 0)
    for j = 0; j < remaining.length(); j = j + 1 {
      remaining[j] = ac.ciphertext[i + j]
    }
    let xi = self.dec_last(remaining)
    for j = 0; j < remaining.length(); j = j + 1 {
      msg[i + j] = xi[j]
    }
  }
  let ad_length = if ad.is_empty() { 0 } else { ad.unwrap().length() }
  let tag = self.mac(ad_length, msg_length)
  let mut dt = 0
  for i = 0; i < tag.length(); i = i + 1 {
    dt = dt.lor(tag[i].lxor(ac.tag[i]))
  }
  if dt != 0 {
    return Err("Verification failed")
  }
  return Ok(msg)
}
