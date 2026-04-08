//! SHA-256 Hardware Accelerator Test
//!
//! This example tests the SHA256 hardware accelerator against NIST test vectors.

#![no_std]
#![no_main]

use panic_halt as _;
use rp235x_hal as hal;

use hal::{
    clocks::init_clocks_and_plls,
    pac,
    sha256::{Endianness, Sha256, Sha256State},
    Watchdog,
};

use hal::clocks::Clock;
use hal::fugit::RateExtU32;
use hal::uart::{DataBits, StopBits, UartConfig};

const XTAL_FREQ_HZ: u32 = 12_000_000u32;

// NIST test vectors

// hash of b"" (empty string)
const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

// hash of b"abc"
const ABC_HASH: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

// hash of b"abcdefghijklmnopqrstuvwxyz"
const EXPECTED_LONG: [u8; 32] = [
    0x71, 0xc4, 0x80, 0xdf, 0x93, 0xd6, 0xae, 0x2f, 0x1e, 0xfa, 0xd1, 0x44, 0x7c, 0x66, 0xc9, 0x52,
    0x5e, 0x31, 0x62, 0x18, 0xcf, 0x51, 0xfc, 0x8d, 0x9e, 0xd8, 0x32, 0xf2, 0xda, 0xf1, 0x8b, 0x73,
];

// hash of b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const EXPECTED_MULTI_BLOCK: [u8; 32] = [
    0x83, 0x62, 0x03, 0x94, 0x4f, 0x4c, 0x02, 0x80, 0x46, 0x1a, 0xd7, 0x3d, 0x31, 0x45, 0x7c, 0x22,
    0xba, 0x19, 0xd1, 0xd9, 0x9e, 0x23, 0x2d, 0xc2, 0x31, 0x00, 0x00, 0x85, 0x89, 0x9e, 0x00, 0xa2,
];

// hash of b"hello world"
const EXPECTED_HELLO_WORLD: [u8; 32] = [
    0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
    0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
];

// hash of b"PUCELLE. First, let me tell you whom you have condemn'd: Not one begotten of a shepherd swain, But issued from the progeny of kings; Virtuous and holy, chosen from above, By inspiration of celestial grace, To work exceeding miracles on earth. I never had to do with wicked spirits. But you, that are polluted with your lusts, Stain'd with the guiltless blood of innocents, Corrupt and tainted with a thousand vices, Because you want the grace that others have, You judge it straight a thing impossible To compass wonders but by help of devils. No, misconceived! Joan of Arc hath been A virgin from her tender infancy, Chaste and immaculate in very thought; Whose maiden blood, thus rigorously effused, Will cry for vengeance at the gates of heaven."
// source: https://www.gutenberg.org/cache/epub/100/pg100.txt with apostrophe substitution
const EXPECTED_SHAKESPEARE: [u8; 32] = [
    0x19, 0x42, 0x5f, 0xcc, 0x0a, 0xf2, 0xde, 0x8f, 0x27, 0xd5, 0x60, 0xb9, 0xb3, 0x02, 0x53, 0x08,
    0x30, 0x50, 0x92, 0x0f, 0x6b, 0x82, 0x9a, 0xda, 0x80, 0x40, 0x02, 0xa9, 0x2b, 0xba, 0xf4, 0x90,
];

#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[hal::entry]
fn main() -> ! {
    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = Watchdog::new(pac.WATCHDOG);

    let clocks = init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();

    // The single-cycle I/O block controls our GPIO pins
    let sio = hal::Sio::new(pac.SIO);

    // Set the pins to their default state
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let uart0_pins = (
        // UART TX (characters sent from rp235x) on GPIO0
        pins.gpio0.into_function(),
        // UART RX (characters received by rp235x) on GPIO1
        pins.gpio1.into_function(),
    );

    let uart0 = hal::uart::UartPeripheral::new(pac.UART0, uart0_pins, &mut pac.RESETS)
        .enable(
            UartConfig::new(115200.Hz(), DataBits::Eight, None, StopBits::One),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();

    uart0.write_full_blocking(b"Starting SHA256 example on UART0\r\n");

    let mut sha256 = Sha256::new(pac.SHA256);

    // Test 1: Empty string
    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    let result_empty = state.finish(&mut sha256);
    assert!(result_empty == EMPTY_HASH, "Empty string hash mismatch");
    uart0.write_full_blocking(b"Test 1 (empty): PASS\r\n");

    // Test 2: "abc"
    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    state.update(&mut sha256, b"abc");
    let result_abc = state.finish(&mut sha256);
    assert!(result_abc == ABC_HASH, "abc hash mismatch");
    uart0.write_full_blocking(b"Test 2 (abc): PASS\r\n");

    // Test 3: Longer message
    let data = b"abcdefghijklmnopqrstuvwxyz";
    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    state.update(&mut sha256, data);
    let result_long = state.finish(&mut sha256);

    assert!(result_long == EXPECTED_LONG, "Long string hash mismatch");
    uart0.write_full_blocking(b"Test 3 (long): PASS\r\n");

    // Test 4: Multi-block hash (65 bytes)
    let multi_block_data: [u8; 65] = [b'A'; 65];
    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    state.update(&mut sha256, &multi_block_data);
    let result_multi = state.finish(&mut sha256);
    assert!(
        result_multi == EXPECTED_MULTI_BLOCK,
        "Multi block hash mismatch"
    );

    uart0.write_full_blocking(b"Test 4 (multi-block): PASS\r\n");

    // Test 5: Incremental update
    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    state.update(&mut sha256, b"hello");
    state.update(&mut sha256, b" ");
    state.update(&mut sha256, b"world");
    let result_incremental = state.finish(&mut sha256);

    assert!(
        result_incremental == EXPECTED_HELLO_WORLD,
        "Incremental hash mismatch"
    );
    uart0.write_full_blocking(b"Test 5 (incremental): PASS\r\n");

    let mut state = Sha256State::new();
    state.start(&mut sha256, Endianness::Big);
    state.update(&mut sha256, b"PUCELLE. First, let me tell you whom you have condemn'd: Not one begotten of a shepherd swain, But issued from the progeny of kings; Virtuous and holy, chosen from above, By inspiration of celestial grace, To work exceeding miracles on earth. I never had to do with wicked spirits. But you, that are polluted with your lusts, Stain'd with the guiltless blood of innocents, Corrupt and tainted with a thousand vices, Because you want the grace that others have, You judge it straight a thing impossible To compass wonders but by help of devils. No, misconceived! Joan of Arc hath been A virgin from her tender infancy, Chaste and immaculate in very thought; Whose maiden blood, thus rigorously effused, Will cry for vengeance at the gates of heaven.");
    let result_shakespeare = state.finish(&mut sha256);

    assert!(
        result_shakespeare == EXPECTED_SHAKESPEARE,
        "Long text entry mismatch!"
    );
    uart0.write_full_blocking(b"Test 6 (long text entry): PASS\r\n");

    uart0.write_full_blocking(b"All tests passed.\r\n");

    loop {
        cortex_m::asm::wfi();
    }
}
