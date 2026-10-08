//! The file header (`ELF_LOGFILE_HEADER`) and the end-of-file record
//! (`ELF_EOF_RECORD`).
//!
//! The header is the first 0x30 bytes: its size (0x30), the `LfLe`
//! signature, the version (1.1), where the oldest record starts and where the
//! end-of-file record is, the number the next record will get, the oldest
//! record's number, the maximum size, flags, the retention period and the
//! size again. Windows marks the header dirty while the log is open and only
//! rewrites it on close, so a dirty header's offsets and numbers are stale.
//!
//! The end-of-file record follows the newest record: 0x28 bytes, its size,
//! `0x11111111 0x22222222 0x33333333 0x44444444`, the same four values as
//! the header (start and end offsets, next and oldest record numbers) kept up
//! to date with every write, and its size again.

use common::bytes::Reader;

use crate::Error;

/// The size of the file header, where the ring of records starts.
pub const HEADER_SIZE: usize = 0x30;

/// The signature of the header and of every record, four bytes in.
pub(crate) const SIGNATURE: &[u8; 4] = b"LfLe";

/// Where the signature is in the header and in a record.
pub(crate) const SIGNATURE_OFFSET: usize = 4;

/// The size of the end-of-file record.
pub(crate) const END_OF_FILE_SIZE: usize = 0x28;

/// The four values that mark the end-of-file record, after its size.
const END_OF_FILE_MARKER: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

/// The only version written (1.1).
const VERSION: (u32, u32) = (1, 1);

/// `ELF_LOGFILE_HEADER_DIRTY`: the log was open (not closed cleanly).
const DIRTY: u32 = 0x1;
/// `ELF_LOGFILE_HEADER_WRAP`: records have wrapped around the end.
const WRAPPED: u32 = 0x2;
/// `ELF_LOGFILE_LOGFULL_WRITTEN`: a record was dropped because the log was full.
const LOG_FULL: u32 = 0x4;
/// `ELF_LOGFILE_ARCHIVE_SET`: the archive attribute was set.
const ARCHIVE_SET: u32 = 0x8;

/// The header's flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(pub u32);

impl Flags {
    /// The log was open when copied: the header's offsets and numbers are
    /// stale and the end-of-file record has the current ones.
    #[must_use]
    pub const fn dirty(self) -> bool {
        self.0 & DIRTY != 0
    }

    /// Records have wrapped past the end of the file.
    #[must_use]
    pub const fn wrapped(self) -> bool {
        self.0 & WRAPPED != 0
    }

    /// A record was dropped because the log was full.
    #[must_use]
    pub const fn log_full(self) -> bool {
        self.0 & LOG_FULL != 0
    }

    /// The file's archive attribute was set.
    #[must_use]
    pub const fn archive_set(self) -> bool {
        self.0 & ARCHIVE_SET != 0
    }
}

/// The file header (`ELF_LOGFILE_HEADER`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    /// Its size (`HeaderSize`, 0x30).
    pub size: u32,
    /// `MajorVersion` (1).
    pub major_version: u32,
    /// `MinorVersion` (1).
    pub minor_version: u32,
    /// Where the oldest record starts (`StartOffset`).
    pub start_offset: u32,
    /// Where the end-of-file record starts (`EndOffset`).
    pub end_offset: u32,
    /// The number the next record will get (`CurrentRecordNumber`).
    pub current_record_number: u32,
    /// The oldest record's number (`OldestRecordNumber`).
    pub oldest_record_number: u32,
    /// The most the file may grow to, in bytes (`MaxSize`).
    pub max_size: u32,
    /// `Flags`.
    pub flags: Flags,
    /// How long records are kept, in seconds (`Retention`).
    pub retention: u32,
    /// Its size again (`EndHeaderSize`).
    pub end_size: u32,
}

impl Header {
    /// The header at the start of `data`.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if !has_signature(data) {
            return Err(Error("no LfLe signature at offset 4".to_owned()));
        }
        let mut r = Reader::new(data);
        let field = |r: &mut Reader<'_>| r.u32_le().map_err(|e| Error(e.to_string()));
        let size = field(&mut r)?;
        let _signature = field(&mut r)?;
        Ok(Self {
            size,
            major_version: field(&mut r)?,
            minor_version: field(&mut r)?,
            start_offset: field(&mut r)?,
            end_offset: field(&mut r)?,
            current_record_number: field(&mut r)?,
            oldest_record_number: field(&mut r)?,
            max_size: field(&mut r)?,
            flags: Flags(field(&mut r)?),
            retention: field(&mut r)?,
            end_size: field(&mut r)?,
        })
    }

    /// What is unexpected in it.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.size as usize != HEADER_SIZE || self.end_size as usize != HEADER_SIZE {
            problems.push(format!(
                "header: sizes {:#x} and {:#x}, not {HEADER_SIZE:#x}",
                self.size, self.end_size
            ));
        }
        if (self.major_version, self.minor_version) != VERSION {
            problems.push(format!(
                "header: version {}.{}, not {}.{}",
                self.major_version, self.minor_version, VERSION.0, VERSION.1
            ));
        }
        problems
    }
}

/// Whether `data` has the header's signature.
pub(crate) fn has_signature(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE
        && data.get(SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE.len()) == Some(SIGNATURE)
}

/// The end-of-file record (`ELF_EOF_RECORD`): where the log is, kept current
/// even while the header is dirty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndOfFile {
    /// Where it was found.
    pub offset: u64,
    /// Where the oldest record starts (`BeginRecord`).
    pub begin_record: u32,
    /// Where this record starts (`EndRecord`).
    pub end_record: u32,
    /// The number the next record will get (`CurrentRecordNumber`).
    pub current_record_number: u32,
    /// The oldest record's number (`OldestRecordNumber`).
    pub oldest_record_number: u32,
}

impl EndOfFile {
    /// The end-of-file record in `bytes` (found at `offset`), if they hold
    /// one.
    pub(crate) fn parse(bytes: &[u8], offset: usize) -> Option<Self> {
        let mut r = Reader::new(bytes);
        if r.u32_le().ok()? as usize != END_OF_FILE_SIZE {
            return None;
        }
        for marker in END_OF_FILE_MARKER {
            if r.u32_le().ok()? != marker {
                return None;
            }
        }
        let end_of_file = Self {
            offset: offset as u64,
            begin_record: r.u32_le().ok()?,
            end_record: r.u32_le().ok()?,
            current_record_number: r.u32_le().ok()?,
            oldest_record_number: r.u32_le().ok()?,
        };
        (r.u32_le().ok()? as usize == END_OF_FILE_SIZE).then_some(end_of_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u32, version: (u32, u32)) -> Vec<u8> {
        [
            0x30,
            0x654c_664c,
            version.0,
            version.1,
            0x30,
            0x80,
            7,
            3,
            0x1_0000,
            flags,
            0,
            0x30,
        ]
        .iter()
        .flat_map(|v: &u32| v.to_le_bytes())
        .collect()
    }

    #[test]
    fn reads_the_header_and_its_flags() {
        let parsed = Header::parse(&header(0b1011, VERSION)).unwrap();
        assert_eq!(parsed.current_record_number, 7);
        assert_eq!(parsed.oldest_record_number, 3);
        assert!(parsed.flags.dirty() && parsed.flags.wrapped() && parsed.flags.archive_set());
        assert!(!parsed.flags.log_full());
        assert!(parsed.problems().is_empty());
    }

    #[test]
    fn another_version_is_a_problem() {
        let parsed = Header::parse(&header(0, (2, 0))).unwrap();
        assert_eq!(parsed.problems(), ["header: version 2.0, not 1.1"]);
    }

    #[test]
    fn no_signature_is_an_error() {
        let mut data = header(0, VERSION);
        data[SIGNATURE_OFFSET] = b'X';
        assert!(Header::parse(&data).is_err());
        assert!(Header::parse(&data[..8]).is_err());
    }

    #[test]
    fn reads_the_end_of_file_record() {
        let bytes: Vec<u8> = [
            0x28,
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x30,
            0x90,
            9,
            1,
            0x28,
        ]
        .iter()
        .flat_map(|v: &u32| v.to_le_bytes())
        .collect();
        let end = EndOfFile::parse(&bytes, 0x90).unwrap();
        assert_eq!((end.begin_record, end.end_record), (0x30, 0x90));
        assert_eq!(
            (end.current_record_number, end.oldest_record_number),
            (9, 1)
        );
        assert!(EndOfFile::parse(&bytes[..0x24], 0x90).is_none());
    }
}
