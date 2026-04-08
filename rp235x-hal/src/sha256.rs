//! SHA-256 Hardware Accelerator
//!
//! The RP2350 features a hardware SHA-256 accelerator that can compute
//! cryptographic hash functions much faster than software implementation.
//!
//! See [Section 4.6](https://rptl.io/rp2350-datasheet#section_sha256) of the
//! RP2350 datasheet for more details.
//!
//! ## Features
//!
//! - Hardware-accelerated SHA-256 hashing
//! - Supports both big-endian and little-endian data
//! - Byte swapping for proper SHA-256 format
//! - DMA support for large data transfers (via DREQ_SHA256)
//! - Error detection and recovery
//!
//! ## Basic Usage
//!
//! ```no_run
//! use rp235x_hal::{pac, sha256::{Sha256, Sha256State, Endianness}};
//!
//! let mut peripherals = pac::Peripherals::take().unwrap();
//!
//! // Initialize SHA256 peripheral (no reset needed)
//! let mut sha256 = Sha256::new(peripherals.SHA256);
//!
//! // Create hasher state
//! let mut state = Sha256State::new();
//!
//! // Compute hash
//! let data = b"Hello, World!"; // must be bytes
//! state.start(&mut sha256, Endianness::Big);
//! state.update(&mut sha256, data);
//! state.update(&mut sha256, data); // more data can be appended
//! let result = state.finish(&mut sha256);
//!
//! // result is a 32-byte SHA-256 hash
//! ```
//!
//! ## NIST Test Vectors
//!
//! - SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//! - SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

use crate::pac::sha256;
use crate::pac::SHA256;

/// SHA-256 hash result (32 bytes)
pub type Sha256Result = [u8; 32];

/// Endianness for input/output data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian byte order
    Little,
    /// Big-endian byte order (network order, SHA-256 standard)
    Big,
}

/// SHA-256 peripheral wrapper
///
/// This provides direct register access to the SHA-256 hardware accelerator.
/// For higher-level functionality, use `Sha256State` which handles padding
/// and multi-block hashing.
pub struct Sha256 {
    device: SHA256,
}

unsafe impl Send for Sha256 {}

impl Sha256 {
    /// Take ownership of the SHA256 peripheral
    ///
    /// Note: Unlike other peripherals, SHA256 does not require explicit reset handling.
    /// The hardware is ready to use immediately.
    pub fn new(device: SHA256) -> Self {
        Self { device }
    }

    /// Get the CSR register
    fn csr(&self) -> &sha256::CSR {
        self.device.csr()
    }

    /// Get the WDATA register
    fn wdata(&self) -> &sha256::WDATA {
        self.device.wdata()
    }

    /// Enable or disable byte swapping
    ///
    /// SHA-256 expects bytes in big-endian order, but the system bus is little-endian.
    /// When enabled (default), the hardware will swap bytes automatically.
    ///
    /// # Arguments
    /// * `enable` - `true` to enable byte swapping (recommended for SHA-256),
    ///   `false` to disable
    pub fn set_bswap(&mut self, enable: bool) {
        self.csr().modify(|_, w| w.bswap().bit(enable));
    }

    /// Start a new hash calculation
    ///
    /// This initializes the hardware with the SHA-256 initial hash values
    /// and clears all internal counters.
    pub fn start(&mut self) {
        self.wait_ready_blocking();
        self.clear_err_not_ready();
        self.csr().modify(|_, w| w.start().set_bit());
    }

    /// Check if hardware is ready to accept data
    ///
    /// Returns `true` if the hardware has processed the previous 64-byte block
    /// and is ready to accept more data.
    pub fn is_ready(&self) -> bool {
        self.csr().read().wdata_rdy().bit()
    }

    /// Wait until hardware is ready to accept data.
    pub fn wait_ready_blocking(&self) {
        while !self.is_ready() {
            core::hint::spin_loop();
        }
    }

    /// Check if hash result is valid
    ///
    /// Returns `true` if a complete 64-byte block has been processed
    /// and the result in SUM registers is valid.
    pub fn is_sum_valid(&self) -> bool {
        self.csr().read().sum_vld().bit()
    }

    /// Wait until hash result is valid.
    pub fn wait_valid_blocking(&self) {
        while !self.is_sum_valid() {
            core::hint::spin_loop();
        }
    }

    /// Write one 32-bit word to the hardware
    ///
    /// # Safety
    /// The caller must ensure the hardware is ready
    pub unsafe fn put_word(&self, word: u32) {
        (self.wdata() as *const _ as *mut u32).write_volatile(word);
    }

    /// Write one byte to the hardware
    ///
    /// # Safety
    /// The caller must ensure the hardware is ready
    pub unsafe fn put_byte(&self, byte: u8) {
        (self.wdata() as *const _ as *mut u8).write_volatile(byte);
    }

    /// Clear "not ready" error.
    pub fn clear_err_not_ready(&mut self) {
        self.csr()
            .modify(|_, w| w.err_wdata_not_rdy().clear_bit_by_one());
    }

    /// Read the 256-bit hash result
    ///
    /// # Safety
    /// The caller must ensure the result is valid.
    pub unsafe fn get_result(&self) -> [u32; 8] {
        (self.device.sum0() as *const _ as *const [u32; 8]).read_volatile()
    }
}

/// SHA-256 hashing state
///
/// This maintains the state for incremental hashing, including:
/// - Total data size processed
/// - Cached partial words for unaligned data
/// - Endianness configuration
///
/// ## Example
/// ```no_run
/// use rp235x_hal::{pac, sha256::{Sha256, Sha256State, Endianness}};
///
/// let mut peripherals = pac::Peripherals::take().unwrap();
/// let mut sha256 = Sha256::new(peripherals.SHA256);
///
/// let mut state = Sha256State::new();
/// state.start(&mut sha256, Endianness::Big);
///
/// // Hash data in chunks
/// state.update(&mut sha256, b"Hello, ");
/// state.update(&mut sha256, b"World!");
///
/// let result = state.finish(&mut sha256);
/// ```
pub struct Sha256State {
    endianness: Endianness,
    total_data_size: usize,
    cache: [u8; 4],
    cache_used: u8,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// Create a new SHA-256 state
    pub fn new() -> Self {
        Self {
            endianness: Endianness::Big,
            total_data_size: 0,
            cache: [0; 4],
            cache_used: 0,
        }
    }

    /// Start a new SHA-256 calculation
    ///
    /// # Arguments
    /// * `sha256` - The SHA-256 peripheral instance
    /// * `endianness` - The endianness of the input data
    pub fn start(&mut self, sha256: &mut Sha256, endianness: Endianness) {
        self.endianness = endianness;
        self.total_data_size = 0;
        self.cache_used = 0;
        self.cache = [0; 4];

        sha256.set_bswap(endianness == Endianness::Big);
        sha256.start();
    }

    /// Update hash with data (non-blocking)
    ///
    /// It only uses 32-bit writes; if the data passed to it is not a
    /// multiple of 4 bytes, left over (unaligned) bytes will be cached
    /// for the next update() or will be flushed during finish().
    ///
    /// # Note
    /// This function will block until the SHA256 peripheral is ready
    /// to have data written to it.
    pub fn update(&mut self, sha256: &mut Sha256, data: &[u8]) {
        let mut pos = 0;

        if self.cache_used > 0 {
            while self.cache_used < 4 && pos < data.len() {
                self.cache[self.cache_used as usize] = data[pos];
                self.cache_used += 1;
                pos += 1;
            }

            // If we now have a complete word, write it
            if self.cache_used == 4 {
                let word = u32::from_le_bytes(self.cache);
                sha256.wait_ready_blocking();
                unsafe { sha256.put_word(word) };
                self.cache_used = 0;
            }
        }

        while pos + 4 <= data.len() {
            let word = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            sha256.wait_ready_blocking();
            unsafe { sha256.put_word(word) };
            pos += 4;
        }

        while pos < data.len() {
            // copy any unaligned bytes to cache
            self.cache[self.cache_used as usize] = data[pos];
            self.cache_used += 1;
            pos += 1;
        }

        self.total_data_size += data.len();
    }

    /// Finalize the hash and return the result
    ///
    /// This appends the required padding:
    /// 1. A single 0x80 byte
    /// 2. Zero bytes until the length is congruent to 56 mod 64
    /// 3. The original message length as a 64-bit big-endian integer
    ///
    /// Then waits for the hash to complete and returns the 32-byte result.
    pub fn finish(&mut self, sha256: &mut Sha256) -> Sha256Result {
        // flush remaining bytes in cache
        for i in 0..self.cache_used {
            sha256.wait_ready_blocking();
            unsafe { sha256.put_byte(self.cache[i as usize]) };
        }
        self.cache_used = 0;

        sha256.wait_ready_blocking();
        unsafe { sha256.put_byte(0x80) };

        let msg_len_bits = (self.total_data_size * 8) as u64;
        let bytes_written = self.total_data_size + 1;
        let zero_bytes = if bytes_written % 64 <= 56 {
            56 - (bytes_written % 64)
        } else {
            64 + 56 - (bytes_written % 64)
        };

        for _ in 0..zero_bytes {
            sha256.wait_ready_blocking();
            unsafe { sha256.put_byte(0) };
        }

        let len_bytes = msg_len_bits.to_be_bytes();
        for b in &len_bytes {
            sha256.wait_ready_blocking();
            unsafe { sha256.put_byte(*b) };
        }

        sha256.wait_valid_blocking();

        let result_words = unsafe { sha256.get_result() };
        let mut result = [0u8; 32];
        for i in 0..8 {
            let bytes = result_words[i].to_be_bytes();
            result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        result
    }
}
