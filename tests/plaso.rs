//! plaso's `SysEvent.Evt` (Apache-2.0, `tests/fixtures/plaso/`,
//! gzip-compressed): every one of the 6,501 records plaso's `winevt` parser
//! reads (6,063 in the log's order and 438 recovered from the free space),
//! each as two events, the time generated and the time written, compared on
//! every field plaso reports (`tests/oracle/plaso.tsv.gz`, written from
//! plaso's output).
//!
//! One difference: record 1572, recovered at offset 0x1dff10, is partly
//! overwritten (its length copy is wrong). It says it has 3 strings, and
//! this crate reads 3; plaso (libevt) splits all the bytes from its strings'
//! offset to its data's offset at each NUL and reports 11, the last 8 being
//! the overwritten bytes (`""`, `"d"`, …, `"LSASRV"`, `"WKS-WINXP32BIT"`).
//! plaso reports neither the recovered flag nor the data: the counts of
//! recovered records are those of plaso's own test (`Number of recovered
//! records : 438`).

use std::collections::BTreeSet;
use std::io::Read;

use common::time::Ts;

/// The partly overwritten recovered record plaso reads more strings from.
const OVERWRITTEN: u64 = 0x1d_ff10;
const OVERWRITTEN_NUMBER: u32 = 1572;
const TICKS_PER_SECOND: i64 = 10_000_000;

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn fixture(path: &str) -> Vec<u8> {
    gunzip(&std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap())
}

/// As `tests/oracle/plaso_tsv.py` escapes text.
fn escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '|' => out.push_str("\\|"),
            c => out.push(c),
        }
    }
    out
}

fn seconds(time: Ts) -> i64 {
    time.ticks().map_or(0, |ticks| ticks / TICKS_PER_SECOND)
}

/// The two lines plaso's TSV has for a record.
fn lines(record: &evt::Record) -> [String; 2] {
    [("creation", record.generated), ("written", record.written)].map(|(kind, time)| {
        [
            record.offset.to_string(),
            record.number.to_string(),
            kind.to_owned(),
            seconds(time).to_string(),
            record.code().to_string(),
            record.event_id.to_string(),
            record.facility().to_string(),
            record.severity().value().to_string(),
            record.event_type.value().to_string(),
            record.category.to_string(),
            escape(&record.source),
            escape(&record.computer),
            record.sid.clone().unwrap_or_default(),
            record.strings.len().to_string(),
            record
                .strings
                .iter()
                .map(|s| escape(s))
                .collect::<Vec<_>>()
                .join("|"),
        ]
        .join("\t")
    })
}

#[test]
fn every_record_as_plaso_reads_it() {
    let data = fixture("fixtures/plaso/SysEvent.Evt.gz");
    assert!(evt::detect(&data));
    let log = evt::read(&data).unwrap();
    assert_eq!(
        log.problems,
        [format!(
            "record {OVERWRITTEN_NUMBER} at offset {OVERWRITTEN:#x}: its length copy isn't its length (0x158)"
        )]
    );
    assert_eq!(log.records.len(), 6501);
    assert_eq!(log.records.iter().filter(|r| r.recovered).count(), 438);

    let got: BTreeSet<String> = log.records.iter().flat_map(lines).collect();
    assert_eq!(got.len(), 13_002);
    let oracle = String::from_utf8(fixture("oracle/plaso.tsv.gz")).unwrap();
    let expected: BTreeSet<String> = oracle.lines().map(str::to_owned).collect();
    assert_eq!(expected.len(), 13_002);

    let ours: Vec<&String> = got.difference(&expected).collect();
    let theirs: Vec<&String> = expected.difference(&got).collect();
    assert_eq!((ours.len(), theirs.len()), (2, 2), "{ours:?}\n{theirs:?}");
    for (our, their) in ours.iter().zip(&theirs) {
        assert!(our.starts_with(&format!("{OVERWRITTEN}\t{OVERWRITTEN_NUMBER}\t")));
        let (our_head, our_strings) = our.rsplit_once('\t').unwrap();
        let (their_head, their_strings) = their.rsplit_once('\t').unwrap();
        assert_eq!(
            our_head.rsplit_once('\t').unwrap().0,
            their_head.rsplit_once('\t').unwrap().0
        );
        assert!(our_head.ends_with("\t3") && their_head.ends_with("\t11"));
        assert!(their_strings.starts_with(&format!("{our_strings}|")));
    }
}

#[test]
fn the_dirty_header_and_the_end_of_file_record() {
    let log = evt::read(&fixture("fixtures/plaso/SysEvent.Evt.gz")).unwrap();
    assert!(log.header.flags.dirty() && log.header.flags.wrapped());
    let end = log.end_of_file.unwrap();
    assert_eq!((end.offset, end.begin_record), (0x1b_9674, 0x1e_0130));
    assert_eq!(
        (end.current_record_number, end.oldest_record_number),
        (7455, 1392)
    );
    let live: Vec<u32> = log
        .records
        .iter()
        .filter(|r| !r.recovered)
        .map(|r| r.number)
        .collect();
    assert_eq!(live, (1392..7455).collect::<Vec<_>>());
}

#[test]
fn plaso_s_example_record() {
    let log = evt::read(&fixture("fixtures/plaso/SysEvent.Evt.gz")).unwrap();
    let record = &log.records[0];
    assert_eq!(record.number, 1392);
    assert_eq!(record.generated.to_string(), "2011-07-27T06:41:47.0000000Z");
    assert_eq!(record.event_id, 0x8000_a001);
    assert_eq!(record.code(), 40961);
    assert_eq!(record.severity(), evt::Severity::Warning);
    assert_eq!(record.event_type, evt::EventType::Warning);
    assert_eq!(
        (record.source.as_str(), record.computer.as_str()),
        ("LSASRV", "WKS-WINXP32BIT")
    );
    assert_eq!(record.strings[0], "cifs/CONTROLLER");
}
