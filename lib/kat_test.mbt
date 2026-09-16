///|
fn hex(s : String) -> Bytes {
  @hex.decode(s) catch {
    _ => abort("invalid hex test vector")
  }
}

///|
fn opt(s : String) -> Bytes? {
  if s.length() == 0 {
    None
  } else {
    Some(hex(s))
  }
}

///|
test "AEGIS-128L test vector 1 (tag128)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("")
  let msg = hex("00000000000000000000000000000000")
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("c1c0e58bd913006feba00f4b3cc3594e"))
  assert_eq(ac.tag, hex("abe0ece80c24868a226a35d16bdae37a"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 1 (tag256)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("")
  let msg = hex("00000000000000000000000000000000")
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("c1c0e58bd913006feba00f4b3cc3594e"))
  assert_eq(
    ac.tag,
    hex("25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 2 (tag128)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("")
  let msg = hex("")
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex(""))
  assert_eq(ac.tag, hex("c2b879a67def9d74e6c14f708bbcc9b4"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 2 (tag256)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("")
  let msg = hex("")
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex(""))
  assert_eq(
    ac.tag,
    hex("1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 3 (tag128)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let msg = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"),
  )
  assert_eq(ac.tag, hex("cc6f3372f6aa1bb82388d695c3962d9a"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 3 (tag256)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let msg = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"),
  )
  assert_eq(
    ac.tag,
    hex("022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 4 (tag128)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let msg = hex("000102030405060708090a0b0c0d")
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("79d94593d8c2119d7e8fd9b8fc77"))
  assert_eq(ac.tag, hex("5c04b3dba849b2701effbe32c7f0fab7"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 4 (tag256)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let msg = hex("000102030405060708090a0b0c0d")
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("79d94593d8c2119d7e8fd9b8fc77"))
  assert_eq(
    ac.tag,
    hex("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 5 (tag128)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
  )
  let msg = hex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
  )
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex(
      "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
    ),
  )
  assert_eq(ac.tag, hex("7542a745733014f9474417b337399507"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 5 (tag256)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
  )
  let msg = hex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
  )
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex(
      "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
    ),
  )
  assert_eq(
    ac.tag,
    hex("b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis128L::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-128L test vector 6 (tag128, must fail)" {
  let key = hex("10000200000000000000000000000000")
  let nonce = hex("10010000000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("5c04b3dba849b2701effbe32c7f0fab7"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 6 (tag256, must fail)" {
  let key = hex("10000200000000000000000000000000")
  let nonce = hex("10010000000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 7 (tag128, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc78"),
    tag: hex("5c04b3dba849b2701effbe32c7f0fab7"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 7 (tag256, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc78"),
    tag: hex("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 8 (tag128, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050608")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("5c04b3dba849b2701effbe32c7f0fab7"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 8 (tag256, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050608")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 9 (tag128, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("6c04b3dba849b2701effbe32c7f0fab8"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-128L test vector 9 (tag256, must fail)" {
  let key = hex("10010000000000000000000000000000")
  let nonce = hex("10000200000000000000000000000000")
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("79d94593d8c2119d7e8fd9b8fc77"),
    tag: hex("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad"),
  }
  let aegis = @lib.Aegis128L::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 1 (tag128)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("")
  let msg = hex("00000000000000000000000000000000")
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("754fc3d8c973246dcc6d741412a4b236"))
  assert_eq(ac.tag, hex("3fe91994768b332ed7f570a19ec5896e"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 1 (tag256)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("")
  let msg = hex("00000000000000000000000000000000")
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("754fc3d8c973246dcc6d741412a4b236"))
  assert_eq(
    ac.tag,
    hex("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 2 (tag128)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("")
  let msg = hex("")
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex(""))
  assert_eq(ac.tag, hex("e3def978a0f054afd1e761d7553afba3"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 2 (tag256)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("")
  let msg = hex("")
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex(""))
  assert_eq(
    ac.tag,
    hex("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 3 (tag128)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let msg = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"),
  )
  assert_eq(ac.tag, hex("8d86f91ee606e9ff26a01b64ccbdd91d"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 3 (tag256)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let msg = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"),
  )
  assert_eq(
    ac.tag,
    hex("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 4 (tag128)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let msg = hex("000102030405060708090a0b0c0d")
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("f373079ed84b2709faee37358458"))
  assert_eq(ac.tag, hex("c60b9c2d33ceb058f96e6dd03c215652"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 4 (tag256)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let msg = hex("000102030405060708090a0b0c0d")
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(ac.ciphertext, hex("f373079ed84b2709faee37358458"))
  assert_eq(
    ac.tag,
    hex("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 5 (tag128)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
  )
  let msg = hex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
  )
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex(
      "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
    ),
  )
  assert_eq(ac.tag, hex("ab8a7d53fd0e98d727accca94925e128"))
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 16)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 5 (tag256)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
  )
  let msg = hex(
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
  )
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  let ac = aegis.encrypt_detached(Some(msg), ad)
  assert_eq(
    ac.ciphertext,
    hex(
      "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
    ),
  )
  assert_eq(
    ac.tag,
    hex("a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"),
  )
  // Same result when an empty message is passed as None
  if msg.length() == 0 {
    let aegis = @lib.Aegis256::new(key, nonce, 32)
    let ac2 = aegis.encrypt_detached(None, ad)
    assert_eq(ac2.tag, ac.tag)
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  assert_eq(aegis.decrypt_detached(ac, ad), msg)
}

///|
test "AEGIS-256 test vector 6 (tag128, must fail)" {
  let key = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("c60b9c2d33ceb058f96e6dd03c215652"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 6 (tag256, must fail)" {
  let key = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 7 (tag128, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358459"),
    tag: hex("c60b9c2d33ceb058f96e6dd03c215652"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 7 (tag256, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358459"),
    tag: hex("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 8 (tag128, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050608")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("c60b9c2d33ceb058f96e6dd03c215652"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 8 (tag256, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050608")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 9 (tag128, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("c60b9c2d33ceb058f96e6dd03c215653"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 16)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}

///|
test "AEGIS-256 test vector 9 (tag256, must fail)" {
  let key = hex(
    "1001000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex(
    "1000020000000000000000000000000000000000000000000000000000000000",
  )
  let ad = opt("0001020304050607")
  let ac : @lib.AuthenticatedCiphertext = {
    ciphertext: hex("f373079ed84b2709faee37358458"),
    tag: hex("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da"),
  }
  let aegis = @lib.Aegis256::new(key, nonce, 32)
  try aegis.decrypt_detached(ac, ad) catch {
    Failure(msg) => assert_eq(msg.has_suffix("Verification failed"), true)
    e => fail("unexpected error: \{e}")
  } noraise {
    _ => fail("verification should have failed")
  }
}
