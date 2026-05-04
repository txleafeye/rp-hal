//! SHA-256 Hardware Accelerator
//!
//! The RP2350 features a hardware accelerator that can compute SHA-256  on
//! 64-byte blocks much faster than a software implementation.
//!
//! ## Basic Usage
//! ```no_run
//! use rp235x_hal::{pac, sha256::Sha256};
//!
//! let mut peripherals = pac::Peripherals::take().unwrap();
//! let mut sha256 = Sha256::new(peripherals.SHA256);
//!
//! // Hash data immediately
//! let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
//! sha256.digest(&data);
//! let result = sha256.finalize();
//! // result is a 32-byte SHA-256 hash
//!
//! // Hash data in chunks
//! sha256.digest(b"Hello, ");
//! sha256.digest(b"world!");
//! let result = sha256.finalize();
//! ```

use crate::pac::SHA256;

/// Byte array type to store the 256-bit hash result.
pub type Sha256Result = [u8; 32];

/// Endianness for input/output data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian byte order
    Little,
    /// Big-endian byte order (network order, SHA-256 standard)
    Big,
}

/// SHA-256 peripheral
pub struct Sha256 {
    device: SHA256,
    data_bytes: usize,
    endianness: Endianness,
}

impl Sha256 {
    /// Creates a handle to the SHA-256 hashing peripheral.
    pub fn new(device: SHA256) -> Self {
        Self {
            device,
            data_bytes: 0,
            endianness: Endianness::Big,
        }
    }

    /// Enable or disable byte swapping
    ///
    /// SHA-256 expects bytes in big-endian order, but the system bus is
    /// little-endian.
    pub fn set_bswap(&mut self, endianness: Endianness) {
        self.endianness = endianness;
        self.device
            .csr()
            .modify(|_, w| w.bswap().bit(self.endianness == Endianness::Big));
    }

    /// Write to the SHA256 peripheral's input buffer but do not yet finalize
    /// the hash.
    pub fn digest(&mut self, data: &[u8]) {
        if self.data_bytes == 0 {
            self.wait_ready_blocking();
            self.clear_err_not_ready();
            self.device.csr().modify(|_, w| w.start().set_bit());
        }

        self.data_bytes += data.len();

        for byte in data {
            self.put_byte(*byte);
            self.wait_ready_blocking();
        }
    }

    /// Finalize via padding and return the resulting hash.
    /// Message padding:
    ///     Message M,
    ///     1,
    ///     k zero bits,
    /// where k is the smallest non-negative solution to the equation:
    /// (L + 1 + k = 448) mod 512
    pub fn finalize(&mut self) -> Sha256Result {
        // Call digest with empty data in case it hasn't been called yet.
        self.digest(&[]);

        // write 0b1000_0000
        self.wait_ready_blocking();
        self.put_byte(0x80_u8);

        let bytes_written = self.data_bytes + 1;
        let zero_bytes = if bytes_written % 64 <= 56 {
            56 - (bytes_written % 64)
        } else {
            64 + 56 - (bytes_written % 64)
        };

        for _ in 0..zero_bytes {
            self.wait_ready_blocking();
            self.put_byte(0);
        }

        let len_bytes: [u8; 8] = (self.data_bytes as u64 * 8).to_be_bytes();
        for b in &len_bytes {
            self.wait_ready_blocking();
            self.put_byte(*b);
        }

        self.wait_valid_blocking();

        self.data_bytes = 0;

        let mut result = [0u8; 32];

        let result_words = unsafe {
            // # Safety: this is the only place this is called.
            self.get_result()
        };

        for i in 0..8 {
            let bytes = result_words[i].to_be_bytes();
            result[(i * 4)..(i * 4 + 4)].copy_from_slice(&bytes);
        }
        result
    }

    /// Check if hardware is ready to accept data
    fn is_ready(&self) -> bool {
        self.device.csr().read().wdata_rdy().bit()
    }

    /// Wait until hardware is ready to accept data.
    fn wait_ready_blocking(&self) {
        while !self.is_ready() {
            core::hint::spin_loop();
        }
    }

    /// Check if hash result is valid
    fn is_sum_valid(&self) -> bool {
        self.device.csr().read().sum_vld().bit()
    }

    /// Wait until hash result is valid.
    fn wait_valid_blocking(&self) {
        while !self.is_sum_valid() {
            core::hint::spin_loop();
        }
    }

    /// Gets the FIFO's address.
    fn wdata_address(&self) -> *const u32 {
        self.device.wdata().as_ptr()
    }

    fn put_byte(&self, data: u8) {
        // # Safety:
        // This is the only place WDATA is written.
        unsafe {
            let ptr = self.wdata_address() as *mut u8;
            ptr.write_volatile(data);
        }
    }

    unsafe fn get_result(&self) -> [u32; 8] {
        // # Safety: We're only reading.
        (self.device.sum0().as_ptr() as *const [u32; 8]).read_volatile()
    }

    /// Clear "not ready" error.
    fn clear_err_not_ready(&mut self) {
        self.device
            .csr()
            .modify(|_, w| w.err_wdata_not_rdy().clear_bit_by_one());
    }
}
