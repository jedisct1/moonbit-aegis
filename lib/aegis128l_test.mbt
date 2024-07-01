test "Aegis-128L MAC" {
  let key = Bytes::make(16, init=(1).to_byte())
  let nonce = Bytes::make(16, init=(2).to_byte())
  let tag_length = 32
  let ad = Bytes::make(20, init=(4).to_byte())
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let ac = aegis.encrypt_detached(None, Some(ad))
  //
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let tag2 = aegis.decrypt_detached(ac, Some(ad))?
  //
  for i = 0; i < tag2.length(); i = i + 1 {
    @assertion.assert_eq(ac.tag[i], tag2[i])?
  }
}

test "Aegis-128L roundtrip" {
  let key = Bytes::make(16, init=(1).to_byte())
  let nonce = Bytes::make(16, init=(2).to_byte())
  let tag_length = 32
  let msg = Bytes::make(50)
  for i = 0; i < msg.length(); i = i + 1 {
    msg[i] = i.to_byte()
  }
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), None)
  //
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, None)?
  for i = 0; i < msg.length(); i = i + 1 {
    @assertion.assert_eq(decrypted[i], msg[i])?
  }
}

test "Aegis-128L roundtrip with associated data" {
  let key = Bytes::make(16, init=(1).to_byte())
  let nonce = Bytes::make(16, init=(2).to_byte())
  let tag_length = 32
  let msg = Bytes::make(50)
  for i = 0; i < msg.length(); i = i + 1 {
    msg[i] = i.to_byte()
  }
  let ad = Bytes::make(20, init=(4).to_byte())
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), Some(ad))
  //
  let aegis = Aegis128L::new(key, nonce, tag_length)?
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, Some(ad))?
  for i = 0; i < msg.length(); i = i + 1 {
    @assertion.assert_eq(decrypted[i], msg[i])?
  }
}
