// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Authenticated secret-key encryption.
//!
//! # Use case:
//! `orion::auth` can be used to encrypt messages in a way that detects if an encrypted message has been
//! tampered with before decrypting it.
//!
//! An example of this could be sending messages across networks, where confidentiality
//! of these messages are required.
//!
//! # About:
//! - The nonce is automatically generated.
//! - Returns a vector where the first 24 bytes are the nonce and the rest is the authenticated
//! ciphertext with the last 16 bytes being the corresponding Poly1305 tag.
//! - Uses XChaCha20Poly1305 with no additional data.
//! - When using `seal` and `open` then the seperation of tags, nonces and ciphertext are automatically handeled.
//!
//! # Parameters:
//! - `plaintext`:  The data to be encrypted.
//! - `secret_key`: The secret key used to encrypt the `plaintext`.
//! - `ciphertext_with_tag_and_nonce`:  The data to be decrypted with the first 24 bytes being the nonce and the last
//! 16 bytes being the corresponding Poly1305 tag.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `plaintext` is empty.
//! - `plaintext` is longer than (2^32)-2.
//! - `ciphertext_with_tag_and_nonce` is less than 41 bytes.
//! - `ciphertext_with_tag_and_nonce` is longer than (2^32)-2.
//! - The received tag does not match the calculated tag when calling `aead::open()`.
//! - The `OsRng` fails to initialize or read from its source.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given key. Should this happen,
//! the security of all data that has been encrypted with that given key is compromised.
//! - To securely generate a strong key, use `SecretKey::generate()`.
//!
//! # Example:
//! ```
//! use orion::aead;
//!
//! let secret_key = aead::SecretKey::generate();
//!
//! let ciphertext = aead::seal(&secret_key, "Secret message".as_bytes()).unwrap();
//!
//! let decrypted_data = aead::open(&secret_key, &ciphertext).unwrap();
//! ```

use errors::UnknownCryptoError;
use hazardous::aead;
use hazardous::constants::{POLY1305_BLOCKSIZE, XCHACHA_NONCESIZE};
pub use hazardous::stream::chacha20::SecretKey;
use hazardous::stream::xchacha20::Nonce;

#[must_use]
/// Authenticated encryption using XChaCha20Poly1305.
pub fn seal(secret_key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let nonce = Nonce::generate();

    let mut dst_out = vec![0u8; plaintext.len() + (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE)];
    dst_out[..XCHACHA_NONCESIZE].copy_from_slice(&nonce.as_bytes());

    aead::xchacha20poly1305::seal(
        secret_key,
        &nonce,
        plaintext,
        None,
        &mut dst_out[XCHACHA_NONCESIZE..],
    ).unwrap();

    Ok(dst_out)
}

#[must_use]
/// Authenticated decryption using XChaCha20Poly1305.
pub fn open(
    secret_key: &SecretKey,
    ciphertext_with_tag_and_nonce: &[u8],
) -> Result<Vec<u8>, UnknownCryptoError> {
    // `+ 1` to avoid empty ciphertexts
    if ciphertext_with_tag_and_nonce.len() < (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE + 1) {
        return Err(UnknownCryptoError);
    }

    let mut dst_out =
        vec![0u8; ciphertext_with_tag_and_nonce.len() - (XCHACHA_NONCESIZE + POLY1305_BLOCKSIZE)];

    aead::xchacha20poly1305::open(
        secret_key,
        &Nonce::from_slice(&ciphertext_with_tag_and_nonce[..XCHACHA_NONCESIZE]).unwrap(),
        &ciphertext_with_tag_and_nonce[XCHACHA_NONCESIZE..],
        None,
        &mut dst_out,
    ).unwrap();

    Ok(dst_out)
}

#[test]
fn auth_enc_encryption_decryption() {
    let key = SecretKey::generate();
    let plaintext = "Secret message".as_bytes().to_vec();

    let dst_ciphertext = seal(&key, &plaintext).unwrap();
    assert!(dst_ciphertext.len() == plaintext.len() + (24 + 16));
    let dst_plaintext = open(&key, &dst_ciphertext).unwrap();
    assert!(dst_plaintext.len() == plaintext.len());
    assert_eq!(plaintext, dst_plaintext);
}

#[test]
#[should_panic]
fn auth_enc_plaintext_empty_err() {
    let key = SecretKey::generate();
    let plaintext = "".as_bytes().to_vec();

    seal(&key, &plaintext).unwrap();
}

#[test]
#[should_panic]
fn auth_enc_ciphertext_less_than_31_err() {
    let key = SecretKey::generate();
    let ciphertext = [0u8; 32];

    open(&key, &ciphertext).unwrap();
}

#[test]
#[should_panic]
fn test_modified_nonce_err() {
    let key = SecretKey::generate();
    let plaintext = "Secret message".as_bytes().to_vec();

    let mut dst_ciphertext = seal(&key, &plaintext).unwrap();
    // Modify nonce
    dst_ciphertext[10] ^= 1;
    let _ = open(&key, &dst_ciphertext).unwrap();
}

#[test]
#[should_panic]
fn test_modified_ciphertext_err() {
    let key = SecretKey::generate();
    let plaintext = "Secret message".as_bytes().to_vec();

    let mut dst_ciphertext = seal(&key, &plaintext).unwrap();
    // Modify ciphertext
    dst_ciphertext[25] ^= 1;
    let _ = open(&key, &dst_ciphertext).unwrap();
}

#[test]
#[should_panic]
fn test_diff_secret_key_err() {
    let key = SecretKey::generate();
    let plaintext = "Secret message".as_bytes().to_vec();

    let dst_ciphertext = seal(&key, &plaintext).unwrap();
    let bad_key = SecretKey::generate();
    let _ = open(&bad_key, &dst_ciphertext).unwrap();
}