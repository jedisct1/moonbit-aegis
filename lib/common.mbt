pub struct AuthenticatedCiphertext {
  ciphertext : Bytes
  tag : Bytes
}

fn bytes_array_to_bytes(bytes_array : Array[Int]) -> Bytes {
  let bytes = Bytes::make(bytes_array.length())
  for i = 0; i < bytes_array.length(); i = i + 1 {
    bytes[i] = bytes_array[i].to_byte()
  }
  bytes
}
