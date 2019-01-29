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
#[cfg(feature = "safe_api")]
use rand_os::rand_core::RngCore;
#[cfg(feature = "safe_api")]
use rand_os::OsRng;
use subtle::ConstantTimeEq;

#[must_use]
#[cfg(feature = "safe_api")]
/// Generate random bytes using a CSPRNG. Not available in `no_std` context.
///
/// # About:
/// This function can be used to generate cryptographic keys, salts or other
/// values that rely on strong randomness. Please note that most keys and other
/// types used throughout orion, implement their own `generate()` function and
/// it is strongly preferred to use those, compared to `secure_rand_bytes()`.
///
/// This uses rand_os's [OsRng](https://docs.rs/rand_os/).
///
/// # Parameters:
/// - `dst`: Destination buffer for the randomly generated bytes. The amount of
///   bytes to be generated is
/// implied by the length of `dst`.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The `OsRng` fails to initialize or read from its source.
/// - `dst` is empty.
///
/// # Example:
/// ```
/// use orion::util;
///
/// let mut salt = [0u8; 64];
///
/// util::secure_rand_bytes(&mut salt).unwrap();
/// ```
pub fn secure_rand_bytes(dst: &mut [u8]) -> Result<(), errors::UnknownCryptoError> {
	if dst.is_empty() {
		return Err(errors::UnknownCryptoError);
	}

	let mut generator = OsRng::new()?;
	generator.try_fill_bytes(dst)?;

	Ok(())
}

#[must_use]
/// Compare two equal length slices in constant time.
///
/// # About:
/// Compare two equal length slices, in constant time, using the
/// [subtle](https://crates.io/crates/subtle) crate.
///
/// # Parameters:
/// - `a`: The first slice used in the comparison.
/// - `b`: The second slice used in the comparison.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `a` and `b` do not have the same length.
/// - `a` is not equal to `b`.
///
/// # Example:
/// ```
/// use orion::util;
///
/// let mut mac = [0u8; 64];
/// assert!(util::secure_cmp(&mac, &[0u8; 64]).unwrap());
///
/// util::secure_rand_bytes(&mut mac).unwrap();
/// assert!(util::secure_cmp(&mac, &[0u8; 64]).is_err());
/// ```
pub fn secure_cmp(a: &[u8], b: &[u8]) -> Result<bool, errors::UnknownCryptoError> {
	if a.len() != b.len() {
		return Err(errors::UnknownCryptoError);
	}

	if a.ct_eq(b).unwrap_u8() == 1 {
		Ok(true)
	} else {
		Err(errors::UnknownCryptoError)
	}
}

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

	assert_eq!(secure_cmp(&buf_1, &buf_2).unwrap(), true);
	assert_eq!(secure_cmp(&buf_2, &buf_1).unwrap(), true);
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
