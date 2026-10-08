//! The circular buffer of records: everything after the header, where a
//! record that reaches the end of the file continues right after the header.

use std::borrow::Cow;

use crate::header::HEADER_SIZE;

/// A log file seen as its ring of records.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ring<'a> {
    file: &'a [u8],
}

impl<'a> Ring<'a> {
    pub(crate) const fn new(file: &'a [u8]) -> Self {
        Self { file }
    }

    /// The whole file.
    pub(crate) const fn file(&self) -> &'a [u8] {
        self.file
    }

    /// How many bytes the ring holds.
    pub(crate) const fn capacity(&self) -> usize {
        self.file.len().saturating_sub(HEADER_SIZE)
    }

    /// Whether `offset` is in the ring.
    pub(crate) const fn contains(&self, offset: usize) -> bool {
        offset >= HEADER_SIZE && offset < self.file.len()
    }

    /// `len` bytes from `offset`, continuing after the header when they
    /// reach the end of the file. None when `offset` isn't in the ring or
    /// `len` is more than it holds.
    pub(crate) fn read(&self, offset: usize, len: usize) -> Option<Cow<'a, [u8]>> {
        if !self.contains(offset) || len > self.capacity() {
            return None;
        }
        let tail = self.file.get(offset..)?;
        if let Some(whole) = tail.get(..len) {
            return Some(Cow::Borrowed(whole));
        }
        let head = self
            .file
            .get(HEADER_SIZE..HEADER_SIZE + (len - tail.len()))?;
        Some(Cow::Owned([tail, head].concat()))
    }

    /// The offset `len` bytes after `offset`, wrapping after the header.
    /// `offset` is in the ring and `len` at most its capacity.
    pub(crate) const fn advance(&self, offset: usize, len: usize) -> usize {
        let end = offset + len;
        if end >= self.file.len() {
            end - self.file.len() + HEADER_SIZE
        } else {
            end
        }
    }

    /// The file ranges `len` bytes from `offset` cover: one, or two when
    /// they wrap.
    pub(crate) fn spans(&self, offset: usize, len: usize) -> Vec<(usize, usize)> {
        let end = offset + len;
        if end <= self.file.len() {
            vec![(offset, end)]
        } else {
            vec![
                (offset, self.file.len()),
                (HEADER_SIZE, end - self.file.len() + HEADER_SIZE),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_across_the_end_from_after_the_header() {
        let file: Vec<u8> = (0..0x40).collect();
        let ring = Ring::new(&file);
        assert_eq!(
            ring.read(0x3e, 4).unwrap().as_ref(),
            [0x3e, 0x3f, 0x30, 0x31]
        );
        assert_eq!(ring.advance(0x3e, 4), 0x32);
        assert_eq!(ring.advance(0x3c, 4), 0x30);
        assert_eq!(ring.spans(0x3e, 4), [(0x3e, 0x40), (0x30, 0x32)]);
        assert!(ring.read(0x3e, 0x11).is_none());
        assert!(ring.read(0x10, 4).is_none());
    }
}
