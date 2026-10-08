//! Windows event logs from Windows NT to XP and Server 2003 (`.evt`:
//! `SysEvent.Evt`, `AppEvent.Evt`, `SecEvent.Evt` in
//! `%SystemRoot%\System32\config`). For the `.evtx` logs of Vista and later,
//! see `sootmark-evtx`.
//!
//! A log is a 0x30-byte header ([`Header`], `ELF_LOGFILE_HEADER`) and a ring
//! of records after it. Windows writes each record ([`Record`],
//! `EVENTLOGRECORD`) after the newest one and keeps an end-of-file record
//! ([`EndOfFile`], `ELF_EOF_RECORD`) right after it; when the file is full it
//! starts again after the header, overwriting the oldest records, and a
//! record that reaches the end of the file continues after the header.
//!
//! The records are read in the log's order, from the oldest (where the
//! end-of-file record says it starts, or the header when there is none) to
//! the end-of-file record. Then the rest of the file (the free space between
//! the end-of-file record and the oldest record, and anything else no record
//! covers) is searched for older records, which come back marked
//! `recovered`, as plaso reports them.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let log = evt::read(&std::fs::read("SysEvent.Evt")?)?;
//! for record in &log.records {
//!     println!(
//!         "{} {} {} {} {:?}",
//!         record.number, record.generated, record.source, record.code(), record.strings
//!     );
//! }
//! # Ok(())
//! # }
//! ```

mod header;
mod record;
mod ring;

pub use header::{EndOfFile, Flags, Header, HEADER_SIZE};
pub use record::{EventType, Record, Severity};

use header::{END_OF_FILE_SIZE, SIGNATURE, SIGNATURE_OFFSET};
use record::{claimed_size, Parsed, MIN_SIZE, PREFIX_SIZE};
use ring::Ring;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Records and the end-of-file record start on four-byte boundaries.
const ALIGNMENT: usize = 4;

/// A log's header, records and what couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// The file header.
    pub header: Header,
    /// The end-of-file record, when found.
    pub end_of_file: Option<EndOfFile>,
    /// The records in the log's order, oldest first, then those recovered
    /// from the rest of the file in file order.
    pub records: Vec<Record>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// Why a file can't be read as an event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Whether `data` starts with an event log's header.
#[must_use]
pub fn detect(data: &[u8]) -> bool {
    header::has_signature(data)
}

/// Read an event log.
///
/// # Errors
/// When it has no header (`LfLe` at offset 4).
pub fn read(data: &[u8]) -> Result<Log, Error> {
    let header = Header::parse(data)?;
    let mut problems = header.problems();
    let ring = Ring::new(data);
    let end_of_file = find_end_of_file(ring, &header);
    let start = end_of_file.map_or(header.start_offset, |end| end.begin_record) as usize;
    if end_of_file.is_none() {
        problems.push(format!(
            "no end-of-file record: reading from the header's start offset {start:#x}"
        ));
    }
    let mut records = in_log_order(ring, start, end_of_file, &mut problems);
    let mut covered: Vec<(usize, usize)> = records
        .iter()
        .flat_map(|(record, size)| ring.spans(record.offset as usize, *size))
        .collect();
    if let Some(end) = end_of_file {
        covered.extend(ring.spans(end.offset as usize, END_OF_FILE_SIZE));
    }
    records.extend(recover(ring, covered, &mut problems));
    Ok(Log {
        header,
        end_of_file,
        records: records.into_iter().map(|(record, _)| record).collect(),
        problems,
    })
}

/// The end-of-file record: where a clean header says it is, or else the
/// newest one in the file.
fn find_end_of_file(ring: Ring<'_>, header: &Header) -> Option<EndOfFile> {
    let at_header_end = || {
        let offset = header.end_offset as usize;
        EndOfFile::parse(&ring.read(offset, END_OF_FILE_SIZE)?, offset)
    };
    if !header.flags.dirty() {
        if let Some(end) = at_header_end() {
            return Some(end);
        }
    }
    let file = ring.file();
    (HEADER_SIZE..file.len())
        .step_by(ALIGNMENT)
        .filter_map(|offset| EndOfFile::parse(file.get(offset..)?, offset))
        .max_by_key(|end| end.current_record_number)
}

/// The records from `start` to the end-of-file record (or, without one, to
/// the first thing that isn't a record or back to `start`), each with its
/// size.
fn in_log_order(
    ring: Ring<'_>,
    start: usize,
    end_of_file: Option<EndOfFile>,
    problems: &mut Vec<String>,
) -> Vec<(Record, usize)> {
    let stop = end_of_file.map(|end| end.offset as usize);
    let mut records = Vec::new();
    let mut offset = start;
    // Each record takes at least MIN_SIZE bytes of the ring.
    for _ in 0..=ring.capacity() / MIN_SIZE {
        if Some(offset) == stop {
            return records;
        }
        if offset == start && !records.is_empty() {
            if stop.is_some() {
                problems.push(
                    "the records came back to the oldest without meeting the end-of-file record"
                        .to_owned(),
                );
            }
            return records;
        }
        let Some((parsed, size)) = record_at(ring, offset, false, problems) else {
            if stop.is_some() {
                problems.push(format!(
                    "no record at offset {offset:#x}, before the end-of-file record"
                ));
            }
            return records;
        };
        records.push((parsed.record, size));
        offset = ring.advance(offset, size);
    }
    problems.push("the records loop around the file".to_owned());
    records
}

/// The records in the parts of the file `covered` doesn't cover, marked
/// recovered.
fn recover(
    ring: Ring<'_>,
    mut covered: Vec<(usize, usize)>,
    problems: &mut Vec<String>,
) -> Vec<(Record, usize)> {
    covered.sort_unstable();
    let mut spans = covered.into_iter().peekable();
    let mut records = Vec::new();
    let file = ring.file();
    let mut offset = HEADER_SIZE;
    while offset + PREFIX_SIZE <= file.len() {
        while spans.next_if(|&(_, end)| end <= offset).is_some() {}
        if let Some(&(start, end)) = spans.peek() {
            if start <= offset {
                offset = end.next_multiple_of(ALIGNMENT);
                continue;
            }
        }
        let signature = file.get(offset + SIGNATURE_OFFSET..offset + PREFIX_SIZE);
        let found = (signature == Some(SIGNATURE))
            .then(|| record_at(ring, offset, true, problems))
            .flatten();
        offset += match found {
            Some((parsed, size)) => {
                let skip = if parsed.intact { size } else { ALIGNMENT };
                records.push((parsed.record, size));
                skip
            }
            None => ALIGNMENT,
        };
    }
    records
}

/// The record at `offset` and its size, when one is there.
fn record_at(
    ring: Ring<'_>,
    offset: usize,
    recovered: bool,
    problems: &mut Vec<String>,
) -> Option<(Parsed, usize)> {
    let size = claimed_size(&ring.read(offset, PREFIX_SIZE)?, ring.capacity())?;
    let bytes = ring.read(offset, size)?;
    let parsed = record::parse(&bytes, offset, recovered, problems)?;
    Some((parsed, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use record::tests::record;

    const MARKER: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn end_of_file(begin: usize, end: usize, next: u32) -> Vec<u8> {
        let mut values = vec![0x28];
        values.extend(MARKER);
        values.extend([begin as u32, end as u32, next, 1, 0x28]);
        words(&values)
    }

    /// A log of `size` bytes: records 1 to 3 from 0x30, the end-of-file
    /// record, then an older record 9 in the free space.
    fn log(size: usize) -> Vec<u8> {
        let mut file = words(&[0x30, 0x654c_664c, 1, 1, 0x30, 0, 4, 1, 0, 1, 0, 0x30]);
        for number in 1..=3 {
            file.extend(record(number, &["text"], &[]));
        }
        let end = file.len();
        file.extend(end_of_file(0x30, end, 4));
        file.extend(record(9, &["old"], &[9]));
        file.resize(size, 0);
        file
    }

    #[test]
    fn reads_in_order_then_recovers_the_free_space() {
        let log = read(&log(0x400)).unwrap();
        assert!(log.problems.is_empty(), "{:?}", log.problems);
        let numbers: Vec<(u32, bool)> = log
            .records
            .iter()
            .map(|r| (r.number, r.recovered))
            .collect();
        assert_eq!(numbers, [(1, false), (2, false), (3, false), (9, true)]);
        assert_eq!(log.end_of_file.map(|e| e.current_record_number), Some(4));
    }

    #[test]
    fn follows_a_record_across_the_end_of_the_file() {
        let first = record(1, &["first"], &[]);
        let second = record(2, &["wraps"], &[2; 8]);
        let split = 0x10;
        let start = 0x30 + 0x100;
        let size = start + first.len() + split;
        let mut file = words(&[
            0x30,
            0x654c_664c,
            1,
            1,
            start as u32,
            0,
            3,
            1,
            0,
            3,
            0,
            0x30,
        ]);
        file.extend(&second[split..]);
        let end = file.len();
        file.extend(end_of_file(start, end, 3));
        file.resize(start, 0);
        file.extend(&first);
        file.extend(&second[..split]);
        assert_eq!(file.len(), size);
        let log = read(&file).unwrap();
        assert!(log.problems.is_empty(), "{:?}", log.problems);
        let strings: Vec<&str> = log.records.iter().map(|r| r.strings[0].as_str()).collect();
        assert_eq!(strings, ["first", "wraps"]);
        assert_eq!(log.records[1].data, [2; 8]);
    }

    #[test]
    fn without_an_end_of_file_record_reads_from_the_header() {
        let mut file = log(0x400);
        let at = file
            .windows(4)
            .position(|w| w == 0x1111_1111_u32.to_le_bytes())
            .unwrap();
        file[at] = 0;
        let log = read(&file).unwrap();
        assert_eq!(log.problems.len(), 1, "{:?}", log.problems);
        assert_eq!(log.records.iter().filter(|r| !r.recovered).count(), 3);
        assert_eq!(log.records.iter().filter(|r| r.recovered).count(), 1);
    }

    #[test]
    fn not_a_log() {
        assert!(read(b"nothing here").is_err());
        assert!(!detect(&[0; 0x30]));
        assert!(detect(&log(0x400)));
    }
}
