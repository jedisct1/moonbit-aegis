///|
test "bench AEGIS-128L encrypt 16KB" (b : @bench.T) {
  let key = Bytes::make(16, b'\x01')
  let nonce = Bytes::make(16, b'\x02')
  let msg = Bytes::makei(16384, i => i.to_byte())
  b.bench(fn() {
    let ac = @lib.Aegis128L::new(key, nonce, 16).encrypt_detached(
      Some(msg),
      None,
    ) catch {
      _ => abort("unreachable")
    }
    b.keep(ac)
  })
}

///|
test "bench AEGIS-128L decrypt 16KB" (b : @bench.T) {
  let key = Bytes::make(16, b'\x01')
  let nonce = Bytes::make(16, b'\x02')
  let msg = Bytes::makei(16384, i => i.to_byte())
  let ac = @lib.Aegis128L::new(key, nonce, 16).encrypt_detached(Some(msg), None)
  b.bench(fn() {
    let pt = @lib.Aegis128L::new(key, nonce, 16).decrypt_detached(ac, None) catch {
      _ => abort("unreachable")
    }
    b.keep(pt)
  })
}

///|
test "bench AEGIS-128L init+mac" (b : @bench.T) {
  let key = Bytes::make(16, b'\x01')
  let nonce = Bytes::make(16, b'\x02')
  let ad = Bytes::make(13, b'\x03')
  b.bench(fn() {
    let ac = @lib.Aegis128L::new(key, nonce, 16).encrypt_detached(
      None,
      Some(ad),
    ) catch {
      _ => abort("unreachable")
    }
    b.keep(ac)
  })
}

///|
test "bench AEGIS-256 encrypt 16KB" (b : @bench.T) {
  let key = Bytes::make(32, b'\x01')
  let nonce = Bytes::make(32, b'\x02')
  let msg = Bytes::makei(16384, i => i.to_byte())
  b.bench(fn() {
    let ac = @lib.Aegis256::new(key, nonce, 16).encrypt_detached(
      Some(msg),
      None,
    ) catch {
      _ => abort("unreachable")
    }
    b.keep(ac)
  })
}

///|
test "bench AEGIS-256 decrypt 16KB" (b : @bench.T) {
  let key = Bytes::make(32, b'\x01')
  let nonce = Bytes::make(32, b'\x02')
  let msg = Bytes::makei(16384, i => i.to_byte())
  let ac = @lib.Aegis256::new(key, nonce, 16).encrypt_detached(Some(msg), None)
  b.bench(fn() {
    let pt = @lib.Aegis256::new(key, nonce, 16).decrypt_detached(ac, None) catch {
      _ => abort("unreachable")
    }
    b.keep(pt)
  })
}

///|
test "bench AEGIS-256 init+mac" (b : @bench.T) {
  let key = Bytes::make(32, b'\x01')
  let nonce = Bytes::make(32, b'\x02')
  let ad = Bytes::make(13, b'\x03')
  b.bench(fn() {
    let ac = @lib.Aegis256::new(key, nonce, 16).encrypt_detached(None, Some(ad)) catch {
      _ => abort("unreachable")
    }
    b.keep(ac)
  })
}
