//! REQ: DSC-003 — AES-128 in CFB-128 mode, written by hand around the `aes` block cipher
//! (ADR-911). RFC 3826 uses the NIST SP 800-38A CFB-128 construction, which the `aes` crate
//! does not provide, and `ring` exposes no raw AES block. The feedback register is the previous
//! ciphertext block; the IV is engineBoots || engineTime || salt.

use aes::Aes128;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::Zeroize;

/// The AES-128 key length, in octets.
pub const KEY_LEN: usize = 16;
/// The CFB-128 IV length, in octets (one block).
pub const IV_LEN: usize = 16;

/// Encrypts `data` in place.
pub fn encrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], data: &mut [u8]) {
    run(key, iv, data, false);
}

/// Decrypts `data` in place.
pub fn decrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], data: &mut [u8]) {
    run(key, iv, data, true);
}

fn run(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], data: &mut [u8], decrypting: bool) {
    // The key schedule inside `Aes128` is zeroized on drop (the `aes` crate's `zeroize` feature).
    let cipher = Aes128::new(&(*key).into());
    let mut reg = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block: Block<Aes128> = reg.into();
        cipher.encrypt_block(&mut block);
        let mut ks: [u8; 16] = block.into();
        // The next feedback block is ciphertext: the output when encrypting, the input when
        // decrypting. A short final block is the last one, so its feedback is never used.
        let mut feedback = [0u8; 16];
        if decrypting {
            for (f, c) in feedback.iter_mut().zip(chunk.iter()) {
                *f = *c;
            }
        }
        for (c, k) in chunk.iter_mut().zip(ks.iter()) {
            *c ^= *k;
        }
        if !decrypting {
            for (f, c) in feedback.iter_mut().zip(chunk.iter()) {
                *f = *c;
            }
        }
        ks.zeroize();
        reg = feedback;
    }
    reg.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38A, F.3.13 CFB128-AES128.Encrypt (the vectors RFC 3826 relies on).
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    const CIPHER: &str = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| {
                s.get(i..i.saturating_add(2))
                    .and_then(|p| u8::from_str_radix(p, 16).ok())
            })
            .collect()
    }

    #[test]
    fn dsc_003_rfc3826_aes_cfb_vectors() {
        let mut data = hex(PLAIN);
        encrypt(&KEY, &IV, &mut data);
        assert_eq!(data, hex(CIPHER));
        decrypt(&KEY, &IV, &mut data);
        assert_eq!(data, hex(PLAIN));
    }

    #[test]
    fn dsc_003_aes_cfb_partial_final_block_is_a_stream_prefix() {
        // CFB is a stream mode: a prefix of the message encrypts to a prefix of the ciphertext.
        let full = hex(PLAIN);
        let mut short = full.get(..37).map(<[u8]>::to_vec).unwrap_or_default();
        encrypt(&KEY, &IV, &mut short);
        assert_eq!(short.as_slice(), hex(CIPHER).get(..37).unwrap_or(&[]));
        decrypt(&KEY, &IV, &mut short);
        assert_eq!(short.as_slice(), full.get(..37).unwrap_or(&[]));
    }
}
