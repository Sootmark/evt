//! Arbitrary bytes, the test log cut anywhere, and the test log with bytes
//! changed at random read or are refused: never a panic.

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;

/// Where the header keeps the oldest record's offset, the end-of-file
/// record's offset and the flags.
const START_OFFSET: usize = 0x10;
const END_OFFSET: usize = 0x14;
const FLAGS: usize = 0x24;
/// Where the test log's end-of-file record keeps the oldest record's offset.
const END_OF_FILE_BEGIN: usize = 0x1b_9674 + 0x14;

fn log() -> &'static [u8] {
    static LOG: OnceLock<Vec<u8>> = OnceLock::new();
    LOG.get_or_init(|| {
        let compressed = include_bytes!("fixtures/plaso/SysEvent.Evt.gz");
        let mut data = Vec::new();
        common::gzip::Decoder::new(&compressed[..])
            .read_to_end(&mut data)
            .unwrap();
        data
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = evt::read(&data);
        let _ = evt::detect(&data);
    }

    #[test]
    fn a_header_and_arbitrary_bytes(tail in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut data = log()[..evt::HEADER_SIZE].to_vec();
        data.extend(tail);
        prop_assert!(evt::read(&data).is_ok());
    }

    #[test]
    fn cut_anywhere(len in 0usize..2_031_616) {
        let data = log();
        let _ = evt::read(&data[..len.min(data.len())]);
    }

    #[test]
    fn offsets_anywhere(start in any::<u32>(), end in any::<u32>(), flags in 0u32..16, begin in any::<u32>()) {
        let mut data = log().to_vec();
        for (at, value) in [(START_OFFSET, start), (END_OFFSET, end), (FLAGS, flags), (END_OF_FILE_BEGIN, begin)] {
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        prop_assert!(evt::read(&data).is_ok());
    }

    #[test]
    fn bytes_changed(changes in proptest::collection::vec((0usize..2_031_616, any::<u8>()), 1..64)) {
        let mut data = log().to_vec();
        let len = data.len();
        for (at, byte) in changes {
            data[at % len] = byte;
        }
        prop_assert!(evt::read(&data).is_ok() || !evt::detect(&data));
    }
}
