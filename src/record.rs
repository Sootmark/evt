//! Event records (`EVENTLOGRECORD`).
//!
//! A record is its length, the `LfLe` signature, its number, the time it was
//! generated and the time it was written (Unix seconds, UTC), the event
//! identifier, the event type, the number of strings, the category, reserved
//! flags, the closing record number, where the strings start, the user SID's
//! length and offset, and the data's length and offset (0x38 bytes); then the
//! source name and the computer name (NUL-terminated UTF-16LE), the SID, the
//! strings (NUL-terminated UTF-16LE), the data, padding to four bytes and the
//! length again. Offsets are from the start of the record.
//!
//! The event identifier is a Windows message identifier: the low 16 bits are
//! the code Event Viewer shows, then 12 bits of facility, a reserved bit, the
//! customer bit and two bits of severity.

use common::bytes::Reader;
use common::text::utf16le;
use common::time::Ts;
use common::win::sid_to_string;

use crate::header::{SIGNATURE, SIGNATURE_OFFSET};

/// The size of a record's fixed part, before the source name.
const FIXED_SIZE: usize = 0x38;

/// The size of the length copy that ends a record.
const LENGTH_COPY_SIZE: usize = 4;

/// The smallest record: its fixed part and the length copy.
pub(crate) const MIN_SIZE: usize = FIXED_SIZE + LENGTH_COPY_SIZE;

/// The bytes a record's length and signature take.
pub(crate) const PREFIX_SIZE: usize = SIGNATURE_OFFSET + SIGNATURE.len();

/// The event identifier's code bits.
const CODE_MASK: u32 = 0xFFFF;
/// Where the facility starts in the event identifier.
const FACILITY_SHIFT: u32 = 16;
/// The facility's bits, once shifted.
const FACILITY_MASK: u32 = 0x0FFF;
/// The customer bit: set for identifiers not defined by Microsoft.
const CUSTOMER_BIT: u32 = 1 << 29;
/// Where the severity starts in the event identifier.
const SEVERITY_SHIFT: u32 = 30;

/// The severity in an event identifier's top two bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// `STATUS_SEVERITY_SUCCESS` (0).
    Success,
    /// `STATUS_SEVERITY_INFORMATIONAL` (1).
    Informational,
    /// `STATUS_SEVERITY_WARNING` (2).
    Warning,
    /// `STATUS_SEVERITY_ERROR` (3).
    Error,
}

impl Severity {
    /// The severity of an event identifier.
    #[must_use]
    pub const fn of(event_id: u32) -> Self {
        match event_id >> SEVERITY_SHIFT {
            0 => Self::Success,
            1 => Self::Informational,
            2 => Self::Warning,
            _ => Self::Error,
        }
    }

    /// Its value (0 to 3).
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Informational => 1,
            Self::Warning => 2,
            Self::Error => 3,
        }
    }
}

/// The type of event, as Event Viewer shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// `EVENTLOG_SUCCESS` (0).
    Success,
    /// `EVENTLOG_ERROR_TYPE` (1).
    Error,
    /// `EVENTLOG_WARNING_TYPE` (2).
    Warning,
    /// `EVENTLOG_INFORMATION_TYPE` (4).
    Information,
    /// `EVENTLOG_AUDIT_SUCCESS` (8).
    AuditSuccess,
    /// `EVENTLOG_AUDIT_FAILURE` (0x10).
    AuditFailure,
    /// Any other value.
    Other(u16),
}

impl EventType {
    /// The type a stored value names.
    #[must_use]
    pub const fn from_value(value: u16) -> Self {
        match value {
            0 => Self::Success,
            1 => Self::Error,
            2 => Self::Warning,
            4 => Self::Information,
            8 => Self::AuditSuccess,
            0x10 => Self::AuditFailure,
            other => Self::Other(other),
        }
    }

    /// Its stored value.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::Success => 0,
            Self::Error => 1,
            Self::Warning => 2,
            Self::Information => 4,
            Self::AuditSuccess => 8,
            Self::AuditFailure => 0x10,
            Self::Other(other) => other,
        }
    }
}

/// An event record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Where it starts in the file.
    pub offset: u64,
    /// Its record number (`RecordNumber`).
    pub number: u32,
    /// When the event happened (`TimeGenerated`, UTC).
    pub generated: Ts,
    /// When it was written to the log (`TimeWritten`, UTC).
    pub written: Ts,
    /// The full event identifier (`EventID`): see [`Record::code`],
    /// [`Record::facility`], [`Record::severity`].
    pub event_id: u32,
    /// `EventType`.
    pub event_type: EventType,
    /// `EventCategory`, defined by the source.
    pub category: u16,
    /// `ReservedFlags`.
    pub reserved_flags: u16,
    /// `ClosingRecordNumber`.
    pub closing_record_number: u32,
    /// The source that logged it (`SourceName`: `Service Control Manager`,
    /// `LSASRV`, …).
    pub source: String,
    /// The computer it was logged on (`Computername`).
    pub computer: String,
    /// The user's SID, when recorded.
    pub sid: Option<String>,
    /// The strings inserted into the source's message.
    pub strings: Vec<String>,
    /// The binary data.
    pub data: Vec<u8>,
    /// Whether it was recovered from the free space rather than read in the
    /// log's order.
    pub recovered: bool,
}

impl Record {
    /// The event code Event Viewer shows: the identifier's low 16 bits.
    #[must_use]
    pub const fn code(&self) -> u16 {
        (self.event_id & CODE_MASK) as u16
    }

    /// The identifier's facility (12 bits).
    #[must_use]
    pub const fn facility(&self) -> u16 {
        ((self.event_id >> FACILITY_SHIFT) & FACILITY_MASK) as u16
    }

    /// The identifier's severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        Severity::of(self.event_id)
    }

    /// Whether the identifier is a customer's, not Microsoft's.
    #[must_use]
    pub const fn is_customer(&self) -> bool {
        self.event_id & CUSTOMER_BIT != 0
    }
}

/// The length a record starting with `prefix` claims, when `prefix` has the
/// signature and the length fits `MIN_SIZE..=max`.
pub(crate) fn claimed_size(prefix: &[u8], max: usize) -> Option<usize> {
    let mut r = Reader::new(prefix);
    let size = r.u32_le().ok()? as usize;
    (r.bytes(SIGNATURE.len()).ok()? == SIGNATURE && (MIN_SIZE..=max).contains(&size))
        .then_some(size)
}

/// A record read from its bytes, and whether its length copy matches.
pub(crate) struct Parsed {
    pub(crate) record: Record,
    pub(crate) intact: bool,
}

/// The record in `bytes` (its whole length, starting at `offset` in the
/// file); damage to `problems`. None when its fixed part isn't there.
pub(crate) fn parse(
    bytes: &[u8],
    offset: usize,
    recovered: bool,
    problems: &mut Vec<String>,
) -> Option<Parsed> {
    let fixed = Fixed::parse(bytes)?;
    let place = format!("record {} at offset {offset:#x}", fixed.number);
    let mut damage = |what: String| problems.push(format!("{place}: {what}"));
    let body = bytes.get(..bytes.len().saturating_sub(LENGTH_COPY_SIZE))?;
    let intact = length_copy(bytes) == Some(bytes.len());
    if !intact {
        damage(format!(
            "its length copy isn't its length ({:#x})",
            bytes.len()
        ));
    }

    let source = text_at(body, FIXED_SIZE);
    let computer = text_at(body, source.next);
    for (name, text) in [("source name", &source), ("computer name", &computer)] {
        if !text.terminated {
            damage(format!("its {name} runs to the end"));
        }
    }
    let sid = fixed.sid(body).unwrap_or_else(|what| {
        damage(what);
        None
    });
    let (strings, unread) = fixed.strings(body);
    if let Some(what) = unread {
        damage(what);
    }
    let data = fixed.data(body).unwrap_or_else(|what| {
        damage(what);
        Vec::new()
    });

    Some(Parsed {
        record: Record {
            offset: offset as u64,
            number: fixed.number,
            generated: Ts::from_unix_seconds(i64::from(fixed.generated)),
            written: Ts::from_unix_seconds(i64::from(fixed.written)),
            event_id: fixed.event_id,
            event_type: EventType::from_value(fixed.event_type),
            category: fixed.category,
            reserved_flags: fixed.reserved_flags,
            closing_record_number: fixed.closing_record_number,
            source: source.text,
            computer: computer.text,
            sid,
            strings,
            data,
            recovered,
        },
        intact,
    })
}

/// The length copy at the end of a record.
fn length_copy(bytes: &[u8]) -> Option<usize> {
    let at = bytes.len().checked_sub(LENGTH_COPY_SIZE)?;
    let mut r = Reader::new(bytes.get(at..)?);
    r.u32_le().ok().map(|size| size as usize)
}

/// A record's fixed part.
struct Fixed {
    number: u32,
    generated: u32,
    written: u32,
    event_id: u32,
    event_type: u16,
    string_count: u16,
    category: u16,
    reserved_flags: u16,
    closing_record_number: u32,
    string_offset: u32,
    sid_length: u32,
    sid_offset: u32,
    data_length: u32,
    data_offset: u32,
}

impl Fixed {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        r.skip(PREFIX_SIZE).ok()?;
        Some(Self {
            number: r.u32_le().ok()?,
            generated: r.u32_le().ok()?,
            written: r.u32_le().ok()?,
            event_id: r.u32_le().ok()?,
            event_type: r.u16_le().ok()?,
            string_count: r.u16_le().ok()?,
            category: r.u16_le().ok()?,
            reserved_flags: r.u16_le().ok()?,
            closing_record_number: r.u32_le().ok()?,
            string_offset: r.u32_le().ok()?,
            sid_length: r.u32_le().ok()?,
            sid_offset: r.u32_le().ok()?,
            data_length: r.u32_le().ok()?,
            data_offset: r.u32_le().ok()?,
        })
    }

    /// The SID, if it has one.
    fn sid(&self, body: &[u8]) -> Result<Option<String>, String> {
        if self.sid_length == 0 {
            return Ok(None);
        }
        let bytes = span(body, self.sid_offset, self.sid_length).ok_or_else(|| {
            format!(
                "its SID ({} bytes at {:#x}) is outside it",
                self.sid_length, self.sid_offset
            )
        })?;
        sid_to_string(bytes)
            .map(|(sid, _)| Some(sid))
            .map_err(|e| format!("its SID: {e}"))
    }

    /// The strings: as many as it says, one after another from where they
    /// start; and why not all of them could be read.
    fn strings(&self, body: &[u8]) -> (Vec<String>, Option<String>) {
        let mut strings = Vec::new();
        if self.string_count == 0 {
            return (strings, None);
        }
        let mut at = self.string_offset as usize;
        if at < FIXED_SIZE || at > body.len() {
            return (
                strings,
                Some(format!("its strings' offset {at:#x} is outside it")),
            );
        }
        for index in 0..self.string_count {
            if at >= body.len() {
                let what = format!("it ends after {index} of its {} strings", self.string_count);
                return (strings, Some(what));
            }
            let text = text_at(body, at);
            strings.push(text.text);
            if !text.terminated {
                return (
                    strings,
                    Some(format!("its string {} runs to the end", index + 1)),
                );
            }
            at = text.next;
        }
        (strings, None)
    }

    /// The binary data.
    fn data(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.data_length == 0 {
            return Ok(Vec::new());
        }
        span(body, self.data_offset, self.data_length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                format!(
                    "its data ({} bytes at {:#x}) is outside it",
                    self.data_length, self.data_offset
                )
            })
    }
}

/// `length` bytes at `offset` in `body`, when they are all there.
fn span(body: &[u8], offset: u32, length: u32) -> Option<&[u8]> {
    let start = offset as usize;
    body.get(start..start.checked_add(length as usize)?)
}

/// NUL-terminated UTF-16LE text.
struct NulTerminated {
    text: String,
    /// Where what follows it starts.
    next: usize,
    /// Whether a NUL ended it (rather than the end of the bytes).
    terminated: bool,
}

/// The text at `at` in `body`, up to a NUL or the end.
fn text_at(body: &[u8], at: usize) -> NulTerminated {
    let rest = body.get(at..).unwrap_or_default();
    let nul = rest.chunks_exact(2).position(|unit| unit == [0, 0]);
    let (units, next) = nul.map_or((rest, body.len()), |n| {
        (rest.get(..n * 2).unwrap_or(rest), at + n * 2 + 2)
    });
    NulTerminated {
        text: utf16le(units).text,
        next,
        terminated: nul.is_some(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A record's bytes with `strings`, the SID S-1-5-18 and `data`.
    pub(crate) fn record(number: u32, strings: &[&str], data: &[u8]) -> Vec<u8> {
        let utf16 = |text: &str| -> Vec<u8> {
            text.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let mut names = utf16("Source");
        names.extend(utf16("HOST"));
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let sid_offset = FIXED_SIZE + names.len();
        let string_offset = sid_offset + sid.len();
        let packed: Vec<u8> = strings.iter().flat_map(|s| utf16(s)).collect();
        let data_offset = string_offset + packed.len();
        let unpadded = data_offset + data.len() + LENGTH_COPY_SIZE;
        let size = unpadded.next_multiple_of(4);
        let mut bytes = Vec::new();
        for value in [
            size as u32,
            0x654c_664c,
            number,
            1_000_000_000,
            1_000_000_001,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(0x8000_a001_u32.to_le_bytes());
        for value in [2_u16, strings.len() as u16, 3, 0] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [
            0,
            string_offset,
            sid.len(),
            sid_offset,
            data.len(),
            data_offset,
        ] {
            bytes.extend((value as u32).to_le_bytes());
        }
        bytes.extend(names);
        bytes.extend(sid);
        bytes.extend(packed);
        bytes.extend(data);
        bytes.resize(size - LENGTH_COPY_SIZE, 0);
        bytes.extend((size as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn reads_every_field() {
        let bytes = record(5, &["one", "", "three"], &[1, 2, 3]);
        let mut problems = Vec::new();
        let parsed = parse(&bytes, 0x30, false, &mut problems).unwrap();
        assert!(parsed.intact);
        assert!(problems.is_empty(), "{problems:?}");
        let r = parsed.record;
        assert_eq!(r.number, 5);
        assert_eq!(r.generated.to_string(), "2001-09-09T01:46:40.0000000Z");
        assert_eq!(r.written.to_string(), "2001-09-09T01:46:41.0000000Z");
        assert_eq!(
            (r.code(), r.facility(), r.severity()),
            (0xa001, 0, Severity::Warning)
        );
        assert!(!r.is_customer());
        assert_eq!((r.event_type, r.category), (EventType::Warning, 3));
        assert_eq!((r.source.as_str(), r.computer.as_str()), ("Source", "HOST"));
        assert_eq!(r.sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(r.strings, ["one", "", "three"]);
        assert_eq!(r.data, [1, 2, 3]);
    }

    #[test]
    fn a_wrong_length_copy_is_reported_and_the_rest_read() {
        let mut bytes = record(5, &["one"], &[]);
        let last = bytes.len() - 1;
        bytes[last] = 0x7f;
        let mut problems = Vec::new();
        let parsed = parse(&bytes, 0x30, true, &mut problems).unwrap();
        assert!(!parsed.intact);
        assert_eq!(parsed.record.strings, ["one"]);
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn strings_past_the_end_are_reported() {
        let mut bytes = record(5, &["one"], &[]);
        bytes[0x1a] = 3;
        let mut problems = Vec::new();
        let parsed = parse(&bytes, 0x30, false, &mut problems).unwrap();
        assert_eq!(
            parsed.record.strings.first().map(String::as_str),
            Some("one")
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    #[test]
    fn claimed_sizes_are_bounded() {
        let bytes = record(5, &[], &[]);
        assert_eq!(claimed_size(&bytes, 0x1000), Some(bytes.len()));
        assert_eq!(claimed_size(&bytes, MIN_SIZE), None);
        assert_eq!(claimed_size(&bytes[..4], 0x1000), None);
    }

    #[test]
    fn identifiers_split_like_windows_message_ids() {
        assert_eq!(Severity::of(0x4000_1b7c), Severity::Informational);
        assert_eq!(Severity::of(0xc000_0000).value(), 3);
        assert_eq!(EventType::from_value(0x10), EventType::AuditFailure);
        assert_eq!(EventType::from_value(3).value(), 3);
    }
}
