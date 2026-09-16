///|
/// Copies the words into an `Int32Array`.
/// A plain JavaScript array would store most of these values as floating point numbers, which is a lot slower.
/// The typed array behaves the same for everything we do with it, and keeps them as integers.
extern "js" fn words_from(words : FixedArray[Int]) -> FixedArray[Int] =
  #| (words) => Int32Array.from(words)
