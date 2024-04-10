pub struct AuthenticatedCiphertext {
  ciphertext : Bytes
  tag : Bytes
}

fn bytes_array_to_bytes(bytes_array : Array[Int]) -> Bytes {
  let bytes = Bytes::make(bytes_array.length(), 0)
  @array.iteri(bytes_array, fn(i, x) -> Unit { bytes[i] = x })
  bytes
}
