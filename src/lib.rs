mod sbox;

use sbox::SBOX;
use std::{marker::PhantomData, ops::Range};

pub const W: Range<u32> = 0..3;
/// All AES operations assume a 32-bit word
pub const WORD: usize = 32;
/// Represents a 32 bit word as 4 bytes
pub const WORD_BYTES: usize = WORD / 8;
/// BLOCK is the Block length in bits of AES cipher text output
/// It is fixed at 128 bits or 4 (32 bit word)
pub const BLOCK_SIZE: usize = 4 * WORD;
/// Represents the 128 bit block size as 16 bytes
pub const BLOCK_BYTES: usize = BLOCK_SIZE as usize / 8;
/// SBOX is the subsitution box for hexideciaml inputs defined in the NIST-FIPS-197#5.1.1-Figure.7
/// The index of each entry corresponds to the decimal representation of the hexidecimal input

/// Mode is a marker trait for the three different key lengths AES can implement (128, 192, 256)
pub trait KeyLength {
    /// Key Length is nubmer of bytes required to represent the key length
    ///
    /// AES 128 = 4 words = 16 bytes
    /// AES 192 = 6 words = 24 bytes
    /// AES 256 = 8 words = 32 bytes
    const KEY_LENGTH: usize;
    /// The Block Size for all configurations of AES is 16 bytes or 128 bit
    const BLOCK_SIZE: usize;
    /// Number of rounds is variable for each key length of AES
    const ROUNDS: usize;

    // fn keylen() -> u32;
    // fn blocksize() -> u32;
    // fn rounds() -> u32;
}

/// AES 128 Bit
///
/// Key Length = 4 words = 16 bytes = 128 bits
/// Block Size = 4 words = 16 bytes = 128 bits
/// Rounds     = 10
pub struct Aes128 {}
impl KeyLength for Aes128 {
    const KEY_LENGTH: usize = 4 * WORD_BYTES;
    const BLOCK_SIZE: usize = BLOCK_BYTES;
    const ROUNDS: usize = 10;
}

/// AES 192 Bit
///
/// Key Length = 6 words = 24 bytes = 192 bits
/// Block Size = 4 words = 16 bytes = 128 bits
/// Rounds     = 12
pub struct Aes192 {}
impl KeyLength for Aes192 {
    const KEY_LENGTH: usize = 6 * WORD_BYTES;
    const BLOCK_SIZE: usize = BLOCK_BYTES;
    const ROUNDS: usize = 12;
}

/// AES 256 Bit
///
/// Key Length = 8 words = 32 bytes = 256 bits
/// Block Size = 4 words = 16 bytes = 128 bits
/// Rounds     = 14
pub struct Aes256 {}
impl KeyLength for Aes256 {
    const KEY_LENGTH: usize = 8 * WORD_BYTES;
    const BLOCK_SIZE: usize = BLOCK_BYTES;
    const ROUNDS: usize = 14;
}

#[derive(Debug)]
pub struct Aes<T: KeyLength> {
    /// Key i the specified length (KeyLength 128, 192, 256)
    key: Vec<u8>,
    /// State is the internal two-dimensional matrix AES performs operations on
    ///
    /// It can be represented as a one-dimensional vector of 32-bit words (4 bytes per word)
    ///
    /// As a result we can index into the vector in 1-word (4-byte) increments
    state: Vec<u8>,
    /// Mode can be one of Aes128, Aes192, Aes256
    mode: PhantomData<T>,
}

/// * Key Expansion
/// 0. Copy the input to the state array
/// 1. Round Function #rounds times
///     (SubBytes, ShiftRows, MixColumns, AddRoundKey)
/// 2. Final Round transformation
///     (not MixColumns)
/// 3. State copied out
impl<T: KeyLength> Aes<T> {
    /// Initialize the AES Aglorithm with the input block and key
    ///
    /// The input must be the same as the BLOCK_SIZE, in this case 128 bits == 4 * 32 bit words == 16 bytes
    ///
    /// The Key is variable length depending on which Key Length AES was configured with:
    /// - 128 bit (16 bytes)
    /// - 192 bit (24 bytes)
    /// - 256 bit (32 bytes)
    fn new(input: Vec<u8>, key: Vec<u8>) -> Self {
        assert_eq!(input.len(), BLOCK_BYTES);
        assert_eq!(key.len(), T::KEY_LENGTH);

        // Initialize state matrix
        let mut state: Vec<u8> = Vec::with_capacity(T::BLOCK_SIZE);
        state = input.clone();

        Self {
            state,
            key,
            mode: PhantomData,
        }
    }

    fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
        left.iter().zip(right).map(|(x, y)| x ^ y).collect()
    }

    /// Key Expansion takes the cipher key `K` and expands it to be BLOCK_SIZE * (ROUNDS + 1)
    ///
    /// The resulting vector is a sequence of 4-byte words [w_i]
    /// where 0 <= i < (BLOCK_SIZE * (ROUNDS +1))
    ///
    /// Nk = T::KEY_LENGTH
    fn key_expansion(&self) {
        let key_len = T::KEY_LENGTH;
        let key_words = T::KEY_LENGTH / WORD_BYTES;
        let schedule_cap = T::BLOCK_SIZE * (T::ROUNDS + 1);
        // W is our key expanded schedule. It is indexed in 1-word (4-byte) increments
        let mut w: Vec<u8> = Vec::with_capacity(schedule_cap);

        // word index is a range of 4 indicies into a byte-array (4 bytes = word)
        // let mut w_i = W.clone();

        // Key Schedule (w) is initialized with the raw cipher key `K` with Key Length T::KEY_LENGTH
        for (i, word) in self.key.chunks(WORD_BYTES).enumerate() {
            w[(i * WORD_BYTES) + 0] = word[0];
            w[(i * WORD_BYTES) + 1] = word[1];
            w[(i * WORD_BYTES) + 2] = word[2];
            w[(i * WORD_BYTES) + 3] = word[3];
        }

        // Starting after the last byte of the original cipher key `K`
        // construct the remaining bytes until the end of our
        //
        // where K <= i < (BLOCK_SIZE * (ROUNDS +1))

        // i is the word index
        let mut i = T::KEY_LENGTH;
        while i < schedule_cap {
            let prev_word = &mut w[(i - WORD_BYTES)..(i)];
            let temp: &mut [u8] = prev_word;
            let curr_word = if i % key_words == 0 {
                Self::rotate_word(temp);
                Self::sub_word(temp);
                let rcon = Self::round_constant(i / key_words).to_le_bytes();
                Self::xor(temp, &rcon);
            } else if key_words == Aes256::KEY_LENGTH / WORD_BYTES && i % key_words == 4 {
            };
        }
    }

    // fn add_round_key() {}

    // fn sub_bytes() {}

    // fn shift_rows() {}

    // fn mix_columns() {}

    /// SubWord is a function which takes a single 4-byte word and subsitutes each byte using the
    /// SBOX subsitution table
    fn sub_word(input: &mut [u8]) {
        unimplemented!()
    }

    /// Rotate Word takes a single 4 byte word and perform a cyclic shift of bytes to the left
    ///
    /// For a given input [b0, b1, b2, b3]
    ///
    /// Rotate Word will cyclicly move all byes to the left to produce the following output
    ///
    /// Output [b1, b2, b3, b0]
    #[inline(always)]
    fn rotate_word(input: &mut [u8]) {
        input.rotate_left(1)
    }

    /// Round Constant is implemented as a 4 byte word where the first byte (0x02) is raised to the
    /// power (i). (i) is the round counter starting at an index of 1 not 0.
    ///
    /// [ 0x02^(i-1), 0x00, 0x00, 0x00 ]
    ///
    /// TODO: Actually impelement this in GF(2^8)
    fn round_constant(i: usize) -> usize {
        match i {
            1 => 0x01000000,
            2 => 0x02000000,
            3 => 0x04000000,
            4 => 0x08000000,
            5 => 0x10000000,
            6 => 0x20000000,
            7 => 0x40000000,
            8 => 0x80000000,
            _ => panic!("I didn't handle this many rounds"),
        }
    }
}

// key expansion
// fn key_expansion(words: u32, key: &[u8], rounds: u32) -> &[u8] {
//     //words
//     let block_size = 4u32;

//     // Vec<&[u8]; 4>
//     let mut key_sequence: &[&[u8; 4]; 4];
//     // let mut key_sequence = Vec::with_capacity(((block_size * 32u32) * (rounds + 1u32)) as usize);

//     // key_len = num bytes * 4 words
//     let key_len = key.len() / words as usize;
//     // word count
//     let mut i = 0usize;
//     while i < key_len {
//         let w = [key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]];
//         key_sequence[i] = &w;
//     }

//     i = key_len;

//     while i < block_size as usize * (rounds as usize + 1) {
//         //
//         let prev = key_sequence[i - 1];

//         // stuff
//         let left = key_sequence[i - key_len];
//         key_sequence[i] = xor(left, prev);
//     }

//     unimplemented!()
// }

// fn xor<'a>(left: &'a [u8; 4], right: &'a [u8; 4]) -> &'a [u8; 4] {
//     left.iter()
//         .zip(right.iter())
//         .map(|(f, s)| f ^ s)
//         .collect::<Vec<u8>>()
//         .as_slice()
//         .try_into()
//         .expect("yo messed up")
// }

//
fn encrypt(size: u8, input: &[u8]) -> &[u8] {
    // generate  round keys
    unimplemented!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn name() {}
}
