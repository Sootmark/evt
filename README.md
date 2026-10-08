# evt

Windows event logs from Windows NT to XP and Server 2003 (`.evt`: `SysEvent.Evt`, `AppEvent.Evt`, `SecEvent.Evt` in `%SystemRoot%\System32\config`): every record in the log's order, and the older records still in the free space. For the `.evtx` logs of Vista and later, see `sootmark-evtx`. One dependency, its sibling `sootmark-common` (times, text, SIDs).

```toml
[dependencies]
sootmark-evt = "0.1"
```

```rust
let log = evt::read(&std::fs::read("SysEvent.Evt")?)?;
for record in &log.records {
    println!("{} {} {} {} {:?}", record.number, record.generated, record.source, record.code(), record.strings);
}
```

## What you get

- `read(bytes)`: the header (version, offsets, record numbers, maximum size, flags: dirty, wrapped, full, archived; retention), the end-of-file record, and each record: offset, number, time generated and time written, the full event identifier (`code()`, `facility()`, `severity()`, `is_customer()`), event type, category, source, computer, user SID, strings, data, and whether it was recovered.
- Records are read in the log's order from the oldest, following the ring across the end of the file back to the header, to the end-of-file record. A dirty header (the log was open) has stale offsets: the end-of-file record is found by searching the file, as Windows keeps it current. The rest of the file is then searched for older records, which come back `recovered`.
- `detect(bytes)`: whether a file is one.
- Damage goes to `problems`, never a panic.

## How it's checked

- plaso's `SysEvent.Evt` (Apache-2.0, `tests/fixtures/plaso/`, a dirty, wrapped System log of Windows XP): every one of the 6,501 records plaso's `winevt` parser reads (6,063 in order, one of them split across the end of the file, and 438 recovered), each as plaso's two events, compared on every field plaso reports: offset, number, both times, event and message identifiers, facility, severity, type, category, source, computer, SID and strings. One difference: recovered record 1572 is partly overwritten; it says it has 3 strings and is read with 3, where plaso splits the bytes up to its data at each NUL and reports 8 more made of the overwritten bytes.
- Unit tests on written records: every field, a record split across the end of the file, no end-of-file record, damaged lengths and strings.
- Property tests: arbitrary bytes, the log cut anywhere, its offsets set anywhere and its bytes changed at random never panic.

## Licence

MIT or Apache-2.0, at your option.
