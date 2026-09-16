///|
test "Aegis-128L MAC" {
  let key = Bytes::make(16, (1).to_byte())
  let nonce = Bytes::make(16, (2).to_byte())
  let tag_length = 32
  let ad = Bytes::make(20, (4).to_byte())
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let ac = aegis.encrypt_detached(None, Some(ad))
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let tag2 = aegis.decrypt_detached(ac, Some(ad))
  assert_eq(ac.tag.length(), tag_length)
  assert_eq(tag2.length(), 0)
}

///|
test "Aegis-128L roundtrip" {
  let key = Bytes::make(16, (1).to_byte())
  let nonce = Bytes::make(16, (2).to_byte())
  let tag_length = 32
  let msg = Bytes::makei(50, i => i.to_byte())
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), None)
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, None)
  assert_eq(decrypted, msg)
}

///|
test "Aegis-128L roundtrip with associated data" {
  let key = Bytes::make(16, (1).to_byte())
  let nonce = Bytes::make(16, (2).to_byte())
  let tag_length = 32
  let msg = Bytes::makei(50, i => i.to_byte())
  let ad = Bytes::make(20, (4).to_byte())
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), Some(ad))
  let aegis = @lib.Aegis128L::new(key, nonce, tag_length)
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, Some(ad))
  assert_eq(decrypted, msg)
}
