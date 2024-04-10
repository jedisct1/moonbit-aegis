pub struct Aegis256 {
  mut state : Array[AesBlock]
  mut tag_length : Int
  mut finalized : Bool
} derive(Debug, Show, Default)

pub fn Aegis256::new(
  key : Bytes,
  nonce : Bytes,
  tag_length : Int
) -> Result[Aegis256, String] {
  @assertion.assert_true(key.length() == 32)?
  @assertion.assert_true(nonce.length() == 32)?
  @assertion.assert_true(tag_length == 16 || tag_length == 32)?

  //
  let k0_bytes = Bytes::make(16, 0)
  let k1_bytes = Bytes::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    k0_bytes[i] = key[i]
  }
  for i = 0; i < 16; i = i + 1 {
    k1_bytes[i] = key[i + 16]
  }
  let n0_bytes = Bytes::make(16, 0)
  let n1_bytes = Bytes::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    n0_bytes[i] = nonce[i]
  }
  for i = 0; i < 16; i = i + 1 {
    n1_bytes[i] = nonce[i + 16]
  }
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
  let k0 = AesBlock::from_bytes(k0_bytes)
  let k1 = AesBlock::from_bytes(k1_bytes)
  let n0 = AesBlock::from_bytes(n0_bytes)
  let n1 = AesBlock::from_bytes(n1_bytes)
  let k0n0 = k0.xor(n0)
  let k1n1 = k1.xor(n1)
  //  
  let s = Array::make(6, AesBlock::default())
  s[0] = k0n0
  s[1] = k1n1
  s[2] = c1
  s[3] = c0
  s[4] = k0.xor(c0)
  s[5] = k1.xor(c1)
  let self : Aegis256 = { tag_length, state: s, finalized: false }
  //
  for i = 0; i < 4; i = i + 1 {
    self.update(k0)
    self.update(k1)
    self.update(k0n0)
    self.update(k1n1)
  }
  //
  Ok(self)
}

fn update(self : Aegis256, m : AesBlock) -> Unit {
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

fn absorb(self : Aegis256, ai : Bytes) -> Unit {
  let t = AesBlock::from_bytes(ai)
  self.update(t)
}

fn enc(self : Aegis256, xi : Bytes) -> Bytes {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]))
  let t = AesBlock::from_bytes(xi)
  let ci = t.xor(z)
  self.update(t)
  return ci.to_bytes()
}

fn dec(self : Aegis256, ci : Bytes) -> Bytes {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]))
  let t = AesBlock::from_bytes(ci)
  let xi = t.xor(z)
  self.update(xi)
  xi.to_bytes()
}

fn dec_last(self : Aegis256, cn : Bytes) -> Bytes {
  let s = self.state
  let z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]))
  let pad = Bytes::make(16, 0)
  let cn_length = cn.length()
  for i = 0; i < cn_length; i = i + 1 {
    pad[i] = cn[i]
  }
  let t = AesBlock::from_bytes(pad)
  let out_bytes = t.xor(z).to_bytes()
  for i = 0; i < 16; i = i + 1 {
    pad[i] = out_bytes[i]
  }
  let xn = Bytes::make(cn_length, 0)
  for i = 0; i < cn_length; i = i + 1 {
    xn[i] = pad[i]
  }
  for i = cn_length; i < 16; i = i + 1 {
    pad[i] = 0
  }
  let v = AesBlock::from_bytes(pad)
  self.update(v)
  xn
}

fn mac(self : Aegis256, ad_len_bytes : Int, msg_len_bytes : Int) -> Bytes {
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
    self.update(t)
  }
  if self.tag_length == 16 {
    return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).to_bytes()
  }
  let tag = Bytes::make(32, 0)
  let t0 = s[0].xor(s[1]).xor(s[2]).to_bytes()
  let t1 = s[3].xor(s[4]).xor(s[5]).to_bytes()
  for i = 0; i < 16; i = i + 1 {
    tag[i] = t0[i]
  }
  for i = 0; i < 16; i = i + 1 {
    tag[16 + i] = t1[i]
  }
  tag
}

pub fn encrypt_detached(
  self : Aegis256,
  msg : Option[Bytes],
  ad : Option[Bytes]
) -> AuthenticatedCiphertext {
  @assertion.assert_true(self.finalized.not()).unwrap()
  //  
  let buf16 = Bytes::make(16, 0)
  let mut i = 0
  if ad.is_empty().not() {
    let ad = ad.unwrap()
    while i + 16 <= ad.length() {
      for j = 0; j < 16; j = j + 1 {
        buf16[j] = ad[i + j]
      }
      self.absorb(buf16)
      i = i + 16
    }
    if ad.length() % 16 != 0 {
      let pad = buf16
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < ad.length() % 16; j = j + 1 {
        pad[j] = ad[i + j]
      }
      self.absorb(pad)
    }
  }
  let ciphertext_length = if msg.is_empty() { 0 } else { msg.unwrap().length() }
  let ciphertext = Bytes::make(ciphertext_length, 0)
  if msg.is_empty().not() {
    let msg = msg.unwrap()
    let mut i = 0
    while i + 16 <= msg.length() {
      for j = 0; j < 16; j = j + 1 {
        buf16[j] = msg[i + j]
      }
      let ci = self.enc(buf16)
      for j = 0; j < 16; j = j + 1 {
        ciphertext[i + j] = ci[j]
      }
      i = i + 16
    }
    if msg.length() % 16 != 0 {
      let pad = buf16
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < msg.length() % 16; j = j + 1 {
        pad[j] = msg[i + j]
      }
      let ci = self.enc(pad)
      for j = 0; j < msg.length() % 16; j = j + 1 {
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
  self : Aegis256,
  ac : AuthenticatedCiphertext,
  ad : Option[Bytes]
) -> Result[Bytes, String] {
  @assertion.assert_true(self.finalized.not()).unwrap()
  //  
  let buf16 = Bytes::make(16, 0)
  let mut i = 0
  if ad.is_empty().not() {
    let ad = ad.unwrap()
    while i + 16 <= ad.length() {
      for j = 0; j < 16; j = j + 1 {
        buf16[j] = ad[i + j]
      }
      self.absorb(buf16)
      i = i + 16
    }
    if ad.length() % 16 != 0 {
      let pad = buf16
      for j = 0; j < pad.length(); j = j + 1 {
        pad[j] = 0
      }
      for j = 0; j < ad.length() % 16; j = j + 1 {
        pad[j] = ad[i + j]
      }
      self.absorb(pad)
    }
  }
  let msg_length = ac.ciphertext.length()
  let msg = Bytes::make(msg_length, 0)
  let mut i = 0
  while i + 16 <= ac.ciphertext.length() {
    for j = 0; j < 16; j = j + 1 {
      buf16[j] = ac.ciphertext[i + j]
    }
    let xi = self.dec(buf16)
    for j = 0; j < 16; j = j + 1 {
      msg[i + j] = xi[j]
    }
    i = i + 16
  }
  if ac.ciphertext.length() % 16 != 0 {
    let remaining = Bytes::make(ac.ciphertext.length() % 16, 0)
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
