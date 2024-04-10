test "Aegis-256 MAC" {
  let key = Bytes::make(32, 1)
  let nonce = Bytes::make(32, 2)
  let tag_length = 32
  let ad = Bytes::make(20, 4)
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let ac = aegis.encrypt_detached(None, Some(ad))
  //
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let tag2 = aegis.decrypt_detached(ac, Some(ad))?
  //
  for i = 0; i < tag2.length(); i = i + 1 {
    @assertion.assert_eq(ac.tag[i], tag2[i])?
  }
}

test "Aegis-256 roundtrip" {
  let key = Bytes::make(32, 1)
  let nonce = Bytes::make(32, 2)
  let tag_length = 32
  let msg = Bytes::make(50, 0)
  for i = 0; i < msg.length(); i = i + 1 {
    msg[i] = i
  }
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), None)
  //
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, None)?
  for i = 0; i < msg.length(); i = i + 1 {
    @assertion.assert_eq(decrypted[i], msg[i])?
  }
}

test "Aegis-256 roundtrip with associated data" {
  let key = Bytes::make(32, 1)
  let nonce = Bytes::make(32, 2)
  let tag_length = 32
  let msg = Bytes::make(50, 0)
  for i = 0; i < msg.length(); i = i + 1 {
    msg[i] = i
  }
  let ad = Bytes::make(20, 4)
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let authenticated_ciphertext = aegis.encrypt_detached(Some(msg), Some(ad))
  //
  let aegis = Aegis256::new(key, nonce, tag_length)?
  let decrypted = aegis.decrypt_detached(authenticated_ciphertext, Some(ad))?
  for i = 0; i < msg.length(); i = i + 1 {
    @assertion.assert_eq(decrypted[i], msg[i])?
  }
}
