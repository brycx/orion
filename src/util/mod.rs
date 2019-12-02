// MIT License

// Copyright (c) 2018-2019 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::errors;
use subtle::ConstantTimeEq;

pub(crate) mod endianness;
pub(crate) mod u32x4;
pub(crate) mod u64x4;

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
#[cfg(feature = "safe_api")]
/// Generate random bytes using a CSPRNG. Not available in `no_std` context.
///
/// # About:
/// This function can be used to generate cryptographic keys, salts or other
/// values that rely on strong randomness. Please note that most keys and other
/// types used throughout orion, implement their own `generate()` function and
/// it is strongly preferred to use those, compared to `secure_rand_bytes()`.
///
/// This uses [`getrandom`].
///
/// # Parameters:
/// - `dst`: Destination buffer for the randomly generated bytes. The amount of
///   bytes to be generated is
/// implied by the length of `dst`.
///
/// # Errors:
/// An error will be returned if:
/// - `dst` is empty.
///
/// # Panics:
/// A panic will occur if:
/// - Failure to generate random bytes securely.
/// - The platform is not supported by [`getrandom`].
///
/// # Example:
/// ```rust
/// use orion::util;
///
/// let mut salt = [0u8; 64];
/// util::secure_rand_bytes(&mut salt)?;
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
/// [`getrandom`]: https://github.com/rust-random/getrandom
pub fn secure_rand_bytes(dst: &mut [u8]) -> Result<(), errors::UnknownCryptoError> {
	if dst.is_empty() {
		return Err(errors::UnknownCryptoError);
	}

	getrandom::getrandom(dst).unwrap();

	Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Compare two equal length slices in constant time.
///
/// # About:
/// Compare two equal length slices, in constant time, using the
/// [subtle](https://github.com/dalek-cryptography/subtle) crate.
///
/// # Parameters:
/// - `a`: The first slice used in the comparison.
/// - `b`: The second slice used in the comparison.
///
/// # Errors:
/// An error will be returned if:
/// - `a` and `b` do not have the same length.
/// - `a` is not equal to `b`.
///
/// # Example:
/// ```rust
/// use orion::util;
///
/// let mut rnd_bytes = [0u8; 64];
/// assert!(util::secure_cmp(&rnd_bytes, &[0u8; 64]).is_ok());
///
/// util::secure_rand_bytes(&mut rnd_bytes)?;
/// assert!(util::secure_cmp(&rnd_bytes, &[0u8; 64]).is_err());
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
pub fn secure_cmp(a: &[u8], b: &[u8]) -> Result<(), errors::UnknownCryptoError> {
	if a.ct_eq(b).into() {
		Ok(())
	} else {
		Err(errors::UnknownCryptoError)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "safe_api")]
	#[test]
	fn rand_key_len_ok() {
		let mut dst = [0u8; 64];
		secure_rand_bytes(&mut dst).unwrap();
	}

	#[cfg(feature = "safe_api")]
	#[test]
	fn rand_key_len_error() {
		let mut dst = [0u8; 0];
		assert!(secure_rand_bytes(&mut dst).is_err());

		let mut dst = [0u8; 0];
		let err = secure_rand_bytes(&mut dst).unwrap_err();
		assert_eq!(err, errors::UnknownCryptoError);
	}

	#[cfg(feature = "safe_api")]
	#[test]
	fn test_ct_eq_ok() {
		let buf_1 = [0x06; 10];
		let buf_2 = [0x06; 10];

		assert!(secure_cmp(&buf_1, &buf_2).is_ok());
		assert!(secure_cmp(&buf_2, &buf_1).is_ok());
	}

	#[test]
	fn test_ct_eq_diff_len() {
		let buf_1 = [0x06; 10];
		let buf_2 = [0x06; 5];

		assert!(secure_cmp(&buf_1, &buf_2).is_err());
		assert!(secure_cmp(&buf_2, &buf_1).is_err());
	}

	#[test]
	fn test_ct_ne() {
		let buf_1 = [0x06; 10];
		let buf_2 = [0x76; 10];

		assert!(secure_cmp(&buf_1, &buf_2).is_err());
		assert!(secure_cmp(&buf_2, &buf_1).is_err());
	}

	#[test]
	fn test_ct_ne_reg() {
		assert!(secure_cmp(&[0], &[0, 1]).is_err());
		assert!(secure_cmp(&[0, 1], &[0]).is_err());
	}

	#[cfg(feature = "safe_api")]
	quickcheck! {
		fn prop_secure_cmp(a: Vec<u8>, b: Vec<u8>) -> bool {
			if a == b {
				secure_cmp(&a, &b).is_ok()
			} else {
				secure_cmp(&a, &b).is_err()
			}
		}
	}
}
