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

//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `initial_counter`: The initial counter value. In most cases, this is `0`.
//! - `ciphertext`: The encrypted data.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the ciphertext/plaintext after
//!   encryption/decryption.
//!
//! `nonce`: "Counters and LFSRs are both acceptable ways of generating unique
//! nonces, as is encrypting a counter using a block cipher with a 64-bit block
//! size such as DES.  Note that it is not acceptable to use a truncation of a
//! counter encrypted with block ciphers with 128-bit or 256-bit blocks,
//! because such a truncation may repeat after a short time." See [RFC](https://tools.ietf.org/html/rfc8439)
//! for more information.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` or `ciphertext`.
//! - `plaintext` or `ciphertext` are empty.
//! - The `initial_counter` is high enough to cause a potential overflow.
//!
//! Even though `dst_out` is allowed to be of greater length than `plaintext`,
//! the `ciphertext` produced by `chacha20`/`xchacha20` will always be of the
//! same length as the `plaintext`.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^32-1 keystream blocks are processed or more than 2^32-1 * 64
//! bytes of data are processed.
//!
//! ### Note:
//! [`keystream_block`] is for use-cases where more control over the keystream
//! used for encryption/decryption is desired. It does not encrypt anything.
//! This function's `counter` parameter is never increased and therefor is not
//! checked for potential overflow on increase either. Only use it if you are
//! absolutely sure you actually need to use it.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen,
//! the security of all data that has been encrypted with that given key is
//! compromised.
//! - Functions herein do not provide any data integrity. If you need
//! data integrity, which is nearly ***always the case***, you should use an
//! AEAD construction instead. See orions [`aead`] module for this.
//! - Only a nonce for XChaCha20 is big enough to be randomly generated using a
//!   CSPRNG.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [XChaCha20Poly1305] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::stream::chacha20;
//!
//! let secret_key = chacha20::SecretKey::generate();
//!
//! let nonce = chacha20::Nonce::from_slice(&[
//! 	0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
//! ])?;
//!
//! // Length of this message is 15
//! let message = "Data to protect".as_bytes();
//!
//! let mut dst_out_pt = [0u8; 15];
//! let mut dst_out_ct = [0u8; 15];
//!
//! chacha20::encrypt(&secret_key, &nonce, 0, message, &mut dst_out_ct)?;
//!
//! chacha20::decrypt(&secret_key, &nonce, 0, &dst_out_ct, &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt, message);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`keystream_block`]: https://docs.rs/orion/latest/orion/hazardous/stream/chacha20/fn.keystream_block.html
//! [`SecretKey::generate()`]: https://docs.rs/orion/latest/orion/hazardous/stream/chacha20/struct.SecretKey.html
//! [`aead`]: https://docs.rs/orion/latest/orion/hazardous/aead/index.html
//! [XChaCha20Poly1305]: https://docs.rs/orion/latest/orion/hazardous/aead/xchacha20poly1305/index.html
use crate::{
	endianness::{load_u32_into_le, store_u32_into_le},
	errors::UnknownCryptoError,
};
use zeroize::Zeroize;

/// The key size for ChaCha20.
pub const CHACHA_KEYSIZE: usize = 32;
/// The nonce size for IETF ChaCha20.
pub const IETF_CHACHA_NONCESIZE: usize = 12;
/// The blocksize which ChaCha20 operates on.
const CHACHA_BLOCKSIZE: usize = 64;
/// The size of the subkey that HChaCha20 returns.
const HCHACHA_OUTSIZE: usize = 32;
/// The nonce size for HChaCha20.
const HCHACHA_NONCESIZE: usize = 16;
/// Type for a ChaCha state represented as an array of 16 32-bit unsigned
/// integers.
type ChaChaState = [u32; 16];

construct_secret_key! {
	/// A type to represent the `SecretKey` that `chacha20`, `xchacha20`, `chacha20poly1305` and
	/// `xchacha20poly1305` use.
	///
	/// # Errors:
	/// An error will be returned if:
	/// - `slice` is not 32 bytes.
	///
	/// # Panics:
	/// A panic will occur if:
	/// - The `OsRng` fails to initialize or read from its source.
	(SecretKey, test_secret_key, CHACHA_KEYSIZE, CHACHA_KEYSIZE, CHACHA_KEYSIZE)
}

impl_from_trait!(SecretKey, CHACHA_KEYSIZE);

construct_public! {
	/// A type that represents a `Nonce` that ChaCha20 and ChaCha20Poly1305 use.
	///
	/// # Errors:
	/// An error will be returned if:
	/// - `slice` is not 12 bytes.
	(Nonce, test_nonce, IETF_CHACHA_NONCESIZE, IETF_CHACHA_NONCESIZE)
}

impl_from_trait!(Nonce, IETF_CHACHA_NONCESIZE);

struct InternalState {
	state: ChaChaState,
	internal_counter: u32,
	is_ietf: bool,
}

impl Drop for InternalState {
	fn drop(&mut self) {
		self.state.zeroize();
	}
}

impl InternalState {
	#[inline]
	/// ChaCha quarter round.
	fn quarter_round(state: &mut ChaChaState, x: usize, y: usize, z: usize, w: usize) {
		state[x] = state[x].wrapping_add(state[y]);
		state[w] ^= state[x];
		state[w] = state[w].rotate_left(16);

		state[z] = state[z].wrapping_add(state[w]);
		state[y] ^= state[z];
		state[y] = state[y].rotate_left(12);

		state[x] = state[x].wrapping_add(state[y]);
		state[w] ^= state[x];
		state[w] = state[w].rotate_left(8);

		state[z] = state[z].wrapping_add(state[w]);
		state[y] ^= state[z];
		state[y] = state[y].rotate_left(7);
	}

	#[inline]
	/// Performs 8 `quarter_round` function calls to process a inner block.
	fn process_inner_block(state: &mut ChaChaState) {
		// Perform column rounds
		Self::quarter_round(state, 0, 4, 8, 12);
		Self::quarter_round(state, 1, 5, 9, 13);
		Self::quarter_round(state, 2, 6, 10, 14);
		Self::quarter_round(state, 3, 7, 11, 15);
		// Perform diagonal rounds
		Self::quarter_round(state, 0, 5, 10, 15);
		Self::quarter_round(state, 1, 6, 11, 12);
		Self::quarter_round(state, 2, 7, 8, 13);
		Self::quarter_round(state, 3, 4, 9, 14);
	}

	#[must_use]
	#[inline]
	/// Initialize either a ChaCha or HChaCha state with a `secret_key` and
	/// `nonce`.
	fn init(
		secret_key: &SecretKey,
		nonce: &[u8],
		is_ietf: bool,
	) -> Result<Self, UnknownCryptoError> {
		if (nonce.len() != IETF_CHACHA_NONCESIZE) && is_ietf {
			return Err(UnknownCryptoError);
		}
		if (nonce.len() != HCHACHA_NONCESIZE) && !is_ietf {
			return Err(UnknownCryptoError);
		}

		let mut internal_state = Self {
			state: [0u32; 16],
			internal_counter: 0,
			is_ietf,
		};

		// Setup state with constants
		internal_state.state[0] = 0x6170_7865_u32;
		internal_state.state[1] = 0x3320_646e_u32;
		internal_state.state[2] = 0x7962_2d32_u32;
		internal_state.state[3] = 0x6b20_6574_u32;

		load_u32_into_le(
			&secret_key.unprotected_as_bytes(),
			&mut internal_state.state[4..12],
		);

		if is_ietf {
			load_u32_into_le(nonce, &mut internal_state.state[13..16]);
		} else {
			load_u32_into_le(nonce, &mut internal_state.state[12..16]);
		}

		Ok(internal_state)
	}

	#[must_use]
	#[inline(always)]
	/// Process either a ChaCha20 or HChaCha20 block.
	fn process_block(
		&mut self,
		block_count: Option<u32>,
	) -> Result<ChaChaState, UnknownCryptoError> {
		if self.is_ietf && block_count.is_none() {
			return Err(UnknownCryptoError);
		}
		if !self.is_ietf && block_count.is_some() {
			return Err(UnknownCryptoError);
		}

		// If this panics, max amount of keystream blocks
		// have been retrieved.
		self.internal_counter = self.internal_counter.checked_add(1).unwrap();

		// Only set block counter if not HChaCha
		if self.is_ietf {
			// .unwrap() cannot panic here since the above two
			// checks make sure block_count.is_some() == true
			self.state[12] = block_count.unwrap();
		}

		let mut working_state = self.state;

		for _ in 0..10 {
			Self::process_inner_block(&mut working_state);
		}

		if self.is_ietf {
			working_state
				.iter_mut()
				.zip(self.state.iter())
				.for_each(|(a, b)| *a = a.wrapping_add(*b));
		}

		Ok(working_state)
	}

	#[must_use]
	#[inline(always)]
	/// Serialize a keystream block of 16 u32's, into a little-endian byte
	/// array.
	fn serialize_block(
		&mut self,
		src_block: &ChaChaState,
		dst_block: &mut [u8],
	) -> Result<(), UnknownCryptoError> {
		if (dst_block.len() != CHACHA_BLOCKSIZE) && self.is_ietf {
			return Err(UnknownCryptoError);
		}
		if (dst_block.len() != HCHACHA_OUTSIZE) && !self.is_ietf {
			return Err(UnknownCryptoError);
		}

		if self.is_ietf {
			store_u32_into_le(src_block, dst_block);
		} else {
			store_u32_into_le(&src_block[0..4], &mut dst_block[0..16]);
			store_u32_into_le(&src_block[12..16], &mut dst_block[16..32]);
		}

		Ok(())
	}
}

#[must_use]
/// IETF ChaCha20 encryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn encrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	plaintext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	if dst_out.len() < plaintext.len() {
		return Err(UnknownCryptoError);
	}
	// Err on empty `plaintext` because the `dst_ciphertext` is user-controlled, so
	// if we don't panic here and just return `dst_ciphertext` when the user
	// encrypts an empty plaintext, they might think the plaintext wasn't empty
	// when checking data in `dst_ciphertext` after encryption
	if plaintext.is_empty() {
		return Err(UnknownCryptoError);
	}

	let mut chacha_state = InternalState::init(secret_key, &nonce.as_ref(), true)?;
	let mut keystream_state: ChaChaState = [0u32; 16];

	for (counter, (plaintext_block, ciphertext_block)) in plaintext
		.chunks(CHACHA_BLOCKSIZE)
		.zip(dst_out.chunks_mut(CHACHA_BLOCKSIZE))
		.enumerate()
	{
		match initial_counter.checked_add(counter as u32) {
			Some(ref block_counter) => {
				keystream_state = chacha_state.process_block(Some(*block_counter))?;
				// We only want to allocate a `keystream_block` if the `ciphertext_block`
				// is not long enough to hold the entire serialized keystream.
				if ciphertext_block.len() == CHACHA_BLOCKSIZE {
					chacha_state.serialize_block(&keystream_state, ciphertext_block)?;
					for (ct_keystream, plaintext) in
						ciphertext_block.iter_mut().zip(plaintext_block.iter())
					{
						*ct_keystream ^= plaintext;
					}
				} else {
					let mut keystream_block = [0u8; CHACHA_BLOCKSIZE];
					chacha_state.serialize_block(&keystream_state, &mut keystream_block)?;

					for (idx, itm) in plaintext_block.iter().enumerate() {
						// `ciphertext_block` and `plaintext_block` have the same length
						// due to chunks(), so indexing is no problem here
						ciphertext_block[idx] = keystream_block[idx] ^ itm;
					}

					keystream_block.zeroize();
				}
			}
			None => return Err(UnknownCryptoError),
		}
	}

	keystream_state.zeroize();

	Ok(())
}

#[must_use]
/// IETF ChaCha20 decryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn decrypt(
	secret_key: &SecretKey,
	nonce: &Nonce,
	initial_counter: u32,
	ciphertext: &[u8],
	dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
	encrypt(secret_key, nonce, initial_counter, ciphertext, dst_out)
}

#[must_use]
/// IETF ChaCha20 block function returning a serialized keystream block.
pub fn keystream_block(
	secret_key: &SecretKey,
	nonce: &Nonce,
	counter: u32,
) -> Result<[u8; CHACHA_BLOCKSIZE], UnknownCryptoError> {
	let mut chacha_state = InternalState::init(secret_key, &nonce.as_ref(), true)?;
	let mut keystream_block = [0u8; CHACHA_BLOCKSIZE];
	let mut keystream_state: ChaChaState = chacha_state.process_block(Some(counter))?;

	chacha_state.serialize_block(&keystream_state, &mut keystream_block)?;

	keystream_state.zeroize();

	Ok(keystream_block)
}

#[must_use]
#[doc(hidden)]
/// HChaCha20 as specified in the [draft-RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub fn hchacha20(
	secret_key: &SecretKey,
	nonce: &[u8],
) -> Result<[u8; HCHACHA_OUTSIZE], UnknownCryptoError> {
	let mut chacha_state = InternalState::init(secret_key, nonce, false)?;
	let mut keystream_state = chacha_state.process_block(None)?;
	let mut keystream_block: [u8; HCHACHA_OUTSIZE] = [0u8; HCHACHA_OUTSIZE];
	chacha_state.serialize_block(&keystream_state, &mut keystream_block)?;

	keystream_state.zeroize();

	Ok(keystream_block)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;
	// One function tested per submodule.

	// encrypt()/decrypt() are tested together here
	// since decrypt() is just a wrapper around encrypt()
	// and so only the decrypt() function is called
	mod test_encrypt_decrypt {
		use super::*;
		#[test]
		fn test_fail_on_initial_counter_overflow() {
			let mut dst = [0u8; 65];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				u32::max_value(),
				&[0u8; 65],
				&mut dst,
			)
			.is_err());
		}

		#[test]
		fn test_pass_on_one_iter_max_initial_counter() {
			let mut dst = [0u8; 64];
			// Should pass because only one iteration is completed, so block_counter will
			// not increase
			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				u32::max_value(),
				&[0u8; 64],
				&mut dst,
			)
			.is_ok());
		}

		#[test]
		fn test_fail_on_empty_plaintext() {
			let mut dst = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
				&[0u8; 0],
				&mut dst,
			)
			.is_err());
		}

		#[test]
		fn test_dst_out_length() {
			let mut dst_small = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
				&[0u8; 128],
				&mut dst_small,
			)
			.is_err());

			let mut dst = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
				&[0u8; 64],
				&mut dst,
			)
			.is_ok());

			let mut dst_big = [0u8; 64];

			assert!(decrypt(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
				&[0u8; 32],
				&mut dst_big,
			)
			.is_ok());
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			/// Given a input length `a` find out how many times
			/// the initial counter on encrypt()/decrypt() would
			/// increase.
			fn counter_increase_times(a: f32) -> u32 {
				// Otherwise a overvlowing subtration would happen
				if a <= 64f32 {
					return 0;
				}

				let check_with_floor = (a / 64f32).floor();
				let actual = a / 64f32;

				assert!(actual >= check_with_floor);
				// Subtract one because the first 64 in length
				// the counter does not increase
				if actual > check_with_floor {
					(actual.ceil() as u32) - 1
				} else {
					(actual as u32) - 1
				}
			}

			quickcheck! {
				// Encrypting input, and then decrypting should always yield the same input.
				fn prop_encrypt_decrypt_same_input(input: Vec<u8>, block_counter: u32) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					// If `block_counter` is high enough check if it would overflow
					if counter_increase_times(pt.len() as f32).checked_add(block_counter).is_none() {
						// Overflow will occur and the operation should fail
						let res = if encrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 12]).unwrap(),
							block_counter,
							&pt[..],
							&mut dst_out_ct,
						).is_err() { true } else { false };

						return res;
					} else {

						encrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 12]).unwrap(),
							block_counter,
							&pt[..],
							&mut dst_out_ct,
						).unwrap();

						decrypt(
							&SecretKey::from_slice(&[0u8; 32]).unwrap(),
							&Nonce::from_slice(&[0u8; 12]).unwrap(),
							block_counter,
							&dst_out_ct[..],
							&mut dst_out_pt,
						).unwrap();

						return dst_out_pt == pt;
					}
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different secret keys and the same nonce
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_keys_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let sk1 = SecretKey::from_slice(&[0u8; 32]).unwrap();
					let sk2 = SecretKey::from_slice(&[1u8; 32]).unwrap();

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&sk1,
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						0,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&sk2,
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						0,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different nonces and the same secret key
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_nonces_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let n1 = Nonce::from_slice(&[0u8; 12]).unwrap();
					let n2 = Nonce::from_slice(&[1u8; 12]).unwrap();

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&n1,
						0,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&n2,
						0,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}

			quickcheck! {
				// Encrypting and decrypting using two different initial counters
				// should never yield the same input.
				fn prop_encrypt_decrypt_diff_init_counter_diff_input(input: Vec<u8>) -> bool {
					let pt = if input.is_empty() {
						vec![1u8; 10]
					} else {
						input
					};

					let init_counter1 = 32;
					let init_counter2 = 64;

					let mut dst_out_ct = vec![0u8; pt.len()];
					let mut dst_out_pt = vec![0u8; pt.len()];

					encrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						init_counter1,
						&pt[..],
						&mut dst_out_ct,
					).unwrap();

					decrypt(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						init_counter2,
						&dst_out_ct[..],
						&mut dst_out_pt,
					).unwrap();

					(dst_out_pt != pt)
				}
			}
		}
	}

	mod test_keystream_block {
		use super::*;

		#[test]
		fn test_counter() {
			// keystream_block never increases the provided counter
			assert!(keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				u32::max_value(),
			)
			.is_ok());

			assert!(keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
			)
			.is_ok());

			assert!(keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				64,
			)
			.is_ok());
		}

		#[test]
		fn test_diff_keys_diff_output() {
			let keystream1 = keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
			)
			.unwrap();

			let keystream2 = keystream_block(
				&SecretKey::from_slice(&[1u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
			)
			.unwrap();

			assert!(keystream1[..] != keystream2[..]);
		}

		#[test]
		fn test_diff_nonce_diff_output() {
			let keystream1 = keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
			)
			.unwrap();

			let keystream2 = keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[1u8; 12]).unwrap(),
				0,
			)
			.unwrap();

			assert!(keystream1[..] != keystream2[..]);
		}

		#[test]
		fn test_diff_initial_counter_diff_output() {
			let keystream1 = keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				0,
			)
			.unwrap();

			let keystream2 = keystream_block(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&Nonce::from_slice(&[0u8; 12]).unwrap(),
				1,
			)
			.unwrap();

			assert!(keystream1[..] != keystream2[..]);
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				fn prop_same_params_same_output(counter: u32) -> bool {
					let keystream1 = keystream_block(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						counter,
					).unwrap();

					let keystream2 = keystream_block(
						&SecretKey::from_slice(&[0u8; 32]).unwrap(),
						&Nonce::from_slice(&[0u8; 12]).unwrap(),
						counter,
					).unwrap();

					(keystream1[..] == keystream2[..])
				}
			}
		}
	}

	mod test_hchacha20 {
		use super::*;

		#[test]
		fn test_nonce_length() {
			assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16],).is_ok());

			assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 17],).is_err());

			assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 15],).is_err());

			assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 0],).is_err());
		}

		#[test]
		fn test_diff_keys_diff_output() {
			let keystream1 =
				hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16]).unwrap();

			let keystream2 =
				hchacha20(&SecretKey::from_slice(&[1u8; 32]).unwrap(), &[0u8; 16]).unwrap();

			assert!(keystream1 != keystream2);
		}

		#[test]
		fn test_diff_nonce_diff_output() {
			let keystream1 =
				hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16]).unwrap();

			let keystream2 =
				hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[1u8; 16]).unwrap();

			assert!(keystream1 != keystream2);
		}
	}
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
	use super::*;
	// One function tested per submodule.

	mod test_init_state {
		use super::*;

		#[test]
		fn test_nonce_length() {
			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 15],
				true
			)
			.is_err());
			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 10],
				true
			)
			.is_err());
			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 12],
				true
			)
			.is_ok());

			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 15],
				false
			)
			.is_err());
			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 17],
				false
			)
			.is_err());
			assert!(InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 16],
				false
			)
			.is_ok());
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				// Always fail to intialize state while the nonce is not
				// the correct length. If it is correct length, never panic.
				fn prop_test_nonce_length_ietf(nonce: Vec<u8>) -> bool {
					let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();

					if nonce.len() != IETF_CHACHA_NONCESIZE {
						let res = if InternalState::init(&sk, &nonce[..], true).is_err() {
							true
						} else {
							false
						};

						return res;
					} else {
						let res = if InternalState::init(&sk, &nonce[..], true).is_ok() {
							true
						} else {
							false
						};

						return res;
					}
				}
			}

			quickcheck! {
				// Always fail to intialize state while the nonce is not
				// the correct length. If it is correct length, never panic.
				fn prop_test_nonce_length_hchacha(nonce: Vec<u8>) -> bool {
					let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();

					if nonce.len() != HCHACHA_NONCESIZE {
						let res = if InternalState::init(&sk, &nonce[..], false).is_err() {
							true
						} else {
							false
						};

						return res;
					} else {
						let res = if InternalState::init(&sk, &nonce[..], false).is_ok() {
							true
						} else {
							false
						};

						return res;
					}
				}
			}
		}
	}

	mod test_process_block {
		use super::*;
		#[test]
		fn test_process_block_wrong_combination_of_variant_and_nonce() {
			let mut chacha_state_ietf = InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 12],
				true,
			)
			.unwrap();
			let mut chacha_state_hchacha = InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 16],
				false,
			)
			.unwrap();

			assert!(chacha_state_hchacha.process_block(Some(1)).is_err());
			assert!(chacha_state_ietf.process_block(None).is_err());
			assert!(chacha_state_hchacha.process_block(None).is_ok());
			assert!(chacha_state_ietf.process_block(Some(1)).is_ok());
		}

		#[test]
		#[should_panic]
		fn test_process_block_panic_on_too_much_keystream_data_ietf() {
			let mut chacha_state_ietf = InternalState {
				state: [0_u32; 16],
				internal_counter: (u32::max_value() - 128),
				is_ietf: true,
			};

			for amount in 0..(128 + 1) {
				let _keystream_block = chacha_state_ietf.process_block(Some(amount as u32));
			}
		}

		#[test]
		#[should_panic]
		fn test_process_block_panic_on_too_much_keystream_data_hchacha() {
			let mut chacha_state_ietf = InternalState {
				state: [0_u32; 16],
				internal_counter: (u32::max_value() - 128),
				is_ietf: false,
			};

			for _ in 0..(128 + 1) {
				let _keystream_block = chacha_state_ietf.process_block(None);
			}
		}
	}

	mod test_serialize_block {
		use super::*;

		#[test]
		fn test_wrong_combination_of_variant_and_dst_out() {
			let mut chacha_state_ietf = InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 12],
				true,
			)
			.unwrap();

			let mut chacha_state_hchacha = InternalState::init(
				&SecretKey::from_slice(&[0u8; 32]).unwrap(),
				&[0u8; 16],
				false,
			)
			.unwrap();

			let mut hchacha_out = [0u8; HCHACHA_OUTSIZE];
			let mut ietf_out = [0u8; CHACHA_BLOCKSIZE];

			let ietf_src = chacha_state_ietf.process_block(Some(1)).unwrap();
			let hchacha_src = chacha_state_hchacha.process_block(None).unwrap();

			assert!(chacha_state_hchacha
				.serialize_block(&hchacha_src, &mut ietf_out)
				.is_err());
			assert!(chacha_state_ietf
				.serialize_block(&ietf_src, &mut hchacha_out)
				.is_err());
			assert!(chacha_state_hchacha
				.serialize_block(&hchacha_src, &mut hchacha_out)
				.is_ok());
			assert!(chacha_state_ietf
				.serialize_block(&ietf_src, &mut ietf_out)
				.is_ok());
		}
	}
}

// Testing any test vectors that aren't put into library's /tests folder.
#[cfg(test)]
mod test_vectors {
	use super::*;

	// Convenience function for testing.
	fn init(key: &[u8], nonce: &[u8]) -> Result<InternalState, UnknownCryptoError> {
		Ok(InternalState::init(
			&SecretKey::from_slice(key)?,
			nonce,
			true,
		)?)
	}

	#[test]
	fn rfc8439_quarter_round_results() {
		let chacha_state = InternalState {
			state: [
				0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0x11111111, 0x01020304, 0x9b8d6f43,
				0x01234567, 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0x11111111, 0x01020304,
				0x9b8d6f43, 0x01234567,
			],
			internal_counter: 0,
			is_ietf: true,
		};
		let expected: [u32; 4] = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];

		let mut wstate = chacha_state.state;

		InternalState::quarter_round(&mut wstate, 0, 1, 2, 3);
		InternalState::quarter_round(&mut wstate, 4, 5, 6, 7);
		InternalState::quarter_round(&mut wstate, 8, 9, 10, 11);
		InternalState::quarter_round(&mut wstate, 12, 13, 14, 15);

		assert_eq!(wstate[0..4], expected);
		assert_eq!(wstate[4..8], expected);
		assert_eq!(wstate[8..12], expected);
		assert_eq!(wstate[12..16], expected);
	}

	#[test]
	fn rfc8439_quarter_round_results_on_indices() {
		let chacha_state = InternalState {
			state: [
				0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
				0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
				0x2098d9d6, 0x91dbd320,
			],
			internal_counter: 0,
			is_ietf: true,
		};
		let expected: ChaChaState = [
			0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
			0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
			0x2098d9d6, 0x91dbd320,
		];

		let mut wstate = chacha_state.state;

		InternalState::quarter_round(&mut wstate, 2, 7, 8, 13);
		assert_eq!(wstate[..], expected);
	}

	#[test]
	fn rfc8439_chacha20_block_results() {
		let key = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
			0x1c, 0x1d, 0x1e, 0x1f,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
		];
		let expected = [
			0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
			0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
			0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
			0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
			0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
		];

		let expected_init: ChaChaState = [
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
			0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
			0x4a000000, 0x00000000,
		];
		// Test initial key-steup
		let mut state = init(&key, &nonce).unwrap();
		state.state[12] = 1_u32;
		assert_eq!(state.state[..], expected_init[..]);

		let keystream_block_from_state = state.process_block(Some(1)).unwrap();
		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			1,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_chacha20_block_test_1() {
		let key = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		let expected = [
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
			0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
			0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
			0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
			0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
		];
		// Unserialized state
		let expected_state: ChaChaState = [
			0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8,
			0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815,
			0x69b687c3, 0x8665eeb2,
		];

		let mut state = init(&key, &nonce).unwrap();
		let keystream_block_from_state = state.process_block(Some(0)).unwrap();
		assert_eq!(keystream_block_from_state[..], expected_state[..]);

		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			0,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_chacha20_block_test_2() {
		let key = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		let expected = [
			0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a, 0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d,
			0x08, 0x0d, 0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69, 0x12, 0xc6, 0x53, 0x3e,
			0x32, 0xee, 0x7a, 0xed, 0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43, 0xd5, 0x71,
			0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5, 0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
			0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
		];
		// Unserialized state
		let expected_state: ChaChaState = [
			0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612,
			0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51,
			0x1f0ae1ac, 0x6f4d794b,
		];

		let mut state = init(&key, &nonce).unwrap();
		let keystream_block_from_state = state.process_block(Some(1)).unwrap();
		assert_eq!(keystream_block_from_state[..], expected_state[..]);

		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			1,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_chacha20_block_test_3() {
		let key = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		let expected = [
			0x3a, 0xeb, 0x52, 0x24, 0xec, 0xf8, 0x49, 0x92, 0x9b, 0x9d, 0x82, 0x8d, 0xb1, 0xce,
			0xd4, 0xdd, 0x83, 0x20, 0x25, 0xe8, 0x01, 0x8b, 0x81, 0x60, 0xb8, 0x22, 0x84, 0xf3,
			0xc9, 0x49, 0xaa, 0x5a, 0x8e, 0xca, 0x00, 0xbb, 0xb4, 0xa7, 0x3b, 0xda, 0xd1, 0x92,
			0xb5, 0xc4, 0x2f, 0x73, 0xf2, 0xfd, 0x4e, 0x27, 0x36, 0x44, 0xc8, 0xb3, 0x61, 0x25,
			0xa6, 0x4a, 0xdd, 0xeb, 0x00, 0x6c, 0x13, 0xa0,
		];
		// Unserialized state
		let expected_state: ChaChaState = [
			0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8,
			0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8,
			0xebdd4aa6, 0xa0136c00,
		];

		let mut state = init(&key, &nonce).unwrap();
		let keystream_block_from_state = state.process_block(Some(1)).unwrap();
		assert_eq!(keystream_block_from_state[..], expected_state[..]);

		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			1,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_chacha20_block_test_4() {
		let key = [
			0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];
		let expected = [
			0x72, 0xd5, 0x4d, 0xfb, 0xf1, 0x2e, 0xc4, 0x4b, 0x36, 0x26, 0x92, 0xdf, 0x94, 0x13,
			0x7f, 0x32, 0x8f, 0xea, 0x8d, 0xa7, 0x39, 0x90, 0x26, 0x5e, 0xc1, 0xbb, 0xbe, 0xa1,
			0xae, 0x9a, 0xf0, 0xca, 0x13, 0xb2, 0x5a, 0xa2, 0x6c, 0xb4, 0xa6, 0x48, 0xcb, 0x9b,
			0x9d, 0x1b, 0xe6, 0x5b, 0x2c, 0x09, 0x24, 0xa6, 0x6c, 0x54, 0xd5, 0x45, 0xec, 0x1b,
			0x73, 0x74, 0xf4, 0x87, 0x2e, 0x99, 0xf0, 0x96,
		];
		// Unserialized state
		let expected_state: ChaChaState = [
			0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1,
			0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5,
			0x87f47473, 0x96f0992e,
		];

		let mut state = init(&key, &nonce).unwrap();
		let keystream_block_from_state = state.process_block(Some(2)).unwrap();
		assert_eq!(keystream_block_from_state[..], expected_state[..]);

		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			2,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_chacha20_block_test_5() {
		let key = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		];
		let expected = [
			0xc2, 0xc6, 0x4d, 0x37, 0x8c, 0xd5, 0x36, 0x37, 0x4a, 0xe2, 0x04, 0xb9, 0xef, 0x93,
			0x3f, 0xcd, 0x1a, 0x8b, 0x22, 0x88, 0xb3, 0xdf, 0xa4, 0x96, 0x72, 0xab, 0x76, 0x5b,
			0x54, 0xee, 0x27, 0xc7, 0x8a, 0x97, 0x0e, 0x0e, 0x95, 0x5c, 0x14, 0xf3, 0xa8, 0x8e,
			0x74, 0x1b, 0x97, 0xc2, 0x86, 0xf7, 0x5f, 0x8f, 0xc2, 0x99, 0xe8, 0x14, 0x83, 0x62,
			0xfa, 0x19, 0x8a, 0x39, 0x53, 0x1b, 0xed, 0x6d,
		];
		// Unserialized state
		let expected_state: ChaChaState = [
			0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72,
			0xc727ee54, 0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8,
			0x398a19fa, 0x6ded1b53,
		];

		let mut state = init(&key, &nonce).unwrap();
		let keystream_block_from_state = state.process_block(Some(0)).unwrap();
		assert_eq!(keystream_block_from_state[..], expected_state[..]);

		let mut ser_block = [0u8; 64];
		state
			.serialize_block(&keystream_block_from_state, &mut ser_block)
			.unwrap();

		let keystream_block_only = keystream_block(
			&SecretKey::from_slice(&key).unwrap(),
			&Nonce::from_slice(&nonce).unwrap(),
			0,
		)
		.unwrap();

		assert_eq!(ser_block[..], expected[..]);
		assert_eq!(ser_block[..], keystream_block_only[..]);
	}

	#[test]
	fn rfc8439_key_schedule() {
		let key = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
			0x1c, 0x1d, 0x1e, 0x1f,
		];
		let nonce = [
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
		];
		// First block setup expected
		let first_state: ChaChaState = [
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
			0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x00000000,
			0x4a000000, 0x00000000,
		];
		// Second block setup expected
		let second_state: ChaChaState = [
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
			0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000002, 0x00000000,
			0x4a000000, 0x00000000,
		];

		// First block operation expected
		let first_block: ChaChaState = [
			0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8, 0x821f138c, 0xe2062c3d, 0xecca4f7e,
			0x78cff39e, 0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed, 0x40ba4c79, 0xcd343ec6,
			0x4c2c21ea, 0xb7417df0,
		];
		// Second block operation expected
		let second_block: ChaChaState = [
			0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec, 0x6d34d426, 0x738cb970, 0x3ac5e9f3,
			0x45590cc4, 0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90, 0x037463f3, 0xa11a2073,
			0xe8bcfb88, 0xedc49139,
		];

		// Expected keystream
		let expected_keystream = [
			0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63,
			0x1d, 0xed, 0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2, 0x7e, 0x4f, 0xca, 0xec,
			0x9e, 0xf3, 0xcf, 0x78, 0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79,
			0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34, 0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
			0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7, 0x69, 0xa6, 0x74, 0x9f, 0x3f, 0x63,
			0x0f, 0x41, 0x22, 0xca, 0xfe, 0x28, 0xec, 0x4d, 0xc4, 0x7e, 0x26, 0xd4, 0x34, 0x6d,
			0x70, 0xb9, 0x8c, 0x73, 0xf3, 0xe9, 0xc5, 0x3a, 0xc4, 0x0c, 0x59, 0x45, 0x39, 0x8b,
			0x6e, 0xda, 0x1a, 0x83, 0x2c, 0x89, 0xc1, 0x67, 0xea, 0xcd, 0x90, 0x1d, 0x7e, 0x2b,
			0xf3, 0x63,
		];

		let mut state = init(&key, &nonce).unwrap();
		// Block call with initial counter
		let first_block_state = state.process_block(Some(1)).unwrap();
		assert_eq!(first_block_state, first_block);
		// Test first internal state
		assert_eq!(first_state, state.state);

		// Next iteration call, increase counter
		let second_block_state = state.process_block(Some(1 + 1)).unwrap();
		assert_eq!(second_block_state, second_block);
		// Test second internal state
		assert_eq!(second_state, state.state);

		let mut actual_keystream = [0u8; 128];
		// Append first keystream block
		state
			.serialize_block(&first_block_state, &mut actual_keystream[..64])
			.unwrap();
		state
			.serialize_block(&second_block_state, &mut actual_keystream[64..])
			.unwrap();
		assert_eq!(
			actual_keystream[..expected_keystream.len()].as_ref(),
			expected_keystream.as_ref()
		);

		actual_keystream[..64].copy_from_slice(
			&keystream_block(
				&SecretKey::from_slice(&key).unwrap(),
				&Nonce::from_slice(&nonce).unwrap(),
				1,
			)
			.unwrap(),
		);
		actual_keystream[64..].copy_from_slice(
			&keystream_block(
				&SecretKey::from_slice(&key).unwrap(),
				&Nonce::from_slice(&nonce).unwrap(),
				1 + 1,
			)
			.unwrap(),
		);

		assert_eq!(
			actual_keystream[..expected_keystream.len()].as_ref(),
			expected_keystream.as_ref()
		);
	}
}
