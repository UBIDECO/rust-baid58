// Base58 encoding extended with HRP and mnemonic checksum information
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023 by
//     Dr. Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright 2023 UBIDECO Institute, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![doc = include_str!("../README.md")]

use std::error::Error;
use std::fmt;
use std::fmt::{Alignment, Display, Formatter, Write};

use base58::{FromBase58, FromBase58Error, ToBase58};
use sha2::Digest;

pub const HRI_MAX_LEN: usize = 8;

pub const CHUNK_POSITIONS_32: [u8; 5] = [6, 8, 8, 8, 8];
pub const CHUNK_POSITIONS_32CHECKSUM: [u8; 5] = [7, 9, 9, 9, 9];

pub const CHUNKING_32: Option<Chunking> = Some(Chunking::new(&CHUNK_POSITIONS_32, '-'));
pub const CHUNKING_32CHECKSUM: Option<Chunking> =
    Some(Chunking::new(&CHUNK_POSITIONS_32CHECKSUM, '-'));

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum MnemonicCase {
    Pascal,
    Kebab,
    Snake,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Chunking {
    positions: &'static [u8],
    separator: char,
}

impl Chunking {
    pub const fn new(positions: &'static [u8], separator: char) -> Self {
        Chunking {
            positions,
            separator,
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid58<const LEN: usize> {
    hri: &'static str,
    chunking: Option<Chunking>,
    payload: [u8; LEN],
}

impl<const LEN: usize> Baid58<LEN> {
    fn new(hri: &'static str, payload: [u8; LEN], chunking: Option<Chunking>) -> Self {
        debug_assert!(hri.len() <= HRI_MAX_LEN, "HRI is too long");
        debug_assert!(LEN > HRI_MAX_LEN, "Baid58 id must be at least 9 bytes");
        #[cfg(debug_assertions)]
        if let Some(chunking) = chunking {
            debug_assert!(!chunking.positions.is_empty());
            let sum = chunking.positions.iter().sum::<u8>() as usize;
            debug_assert!(sum <= LEN * 138 / 100 + 1, "invalid Baid58 separator positions");
        }
        Self {
            hri,
            chunking,
            payload,
        }
    }

    /// # Panics
    ///
    /// If HRI static string is longer than [`HRI_MAX_LEN`]
    pub fn with(hri: &'static str, payload: [u8; LEN]) -> Self { Self::new(hri, payload, None) }

    pub fn with_chunks(
        hri: &'static str,
        payload: [u8; LEN],
        chunk_pos: &'static [u8],
        chunk_sep: char,
    ) -> Self {
        let chunking = Chunking {
            positions: chunk_pos,
            separator: chunk_sep,
        };
        Self::new(hri, payload, Some(chunking))
    }

    pub const fn human_identifier(&self) -> &'static str { self.hri }

    pub fn checksum(&self) -> u32 {
        let key = blake3::Hasher::new().update(self.hri.as_bytes()).finalize();
        let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
        hasher.update(&self.payload);
        let blake = *hasher.finalize().as_bytes();

        let key = sha2::Sha256::digest(self.hri.as_bytes());
        let mut sha = sha2::Sha256::new_with_prefix(key);
        sha.update(&self.payload);
        let sha = sha.finalize();
        u32::from_le_bytes([blake[0], blake[1], sha[0], sha[1]])
    }

    pub fn mnemonic(&self) -> String { self.mnemonic_with_case(MnemonicCase::Kebab) }

    pub fn mnemonic_with_case(&self, case: MnemonicCase) -> String {
        let mn = mnemonic::to_string(self.checksum().to_le_bytes());
        match case {
            MnemonicCase::Pascal => {
                let mut res = String::with_capacity(mn.len());
                for s in mn.split('-') {
                    res.push_str((s[0..1].to_uppercase() + &s[1..]).as_str());
                }
                res
            }
            MnemonicCase::Kebab => mn,
            MnemonicCase::Snake => mn.replace('-', "_"),
        }
    }
}

/// # Use of formatting flags:
///
/// ## HRI, checksum and chunking
///
/// The presence of human-readable identifier and checksum is controlled by precision flag and by
/// alignment flags. All the options can be combined with the mnemonic flags from the next section;
/// if a specific mnemonic flag is present than the checksum is not provided.
///
/// | Flag | HRI    | Checksum          | Mnemonic               | Separators | Example                |
/// |------|--------|-------------------|------------------------|------------|------------------------|
/// | none | absent | absent            | defined by other flags | n/a        |                        |
/// | `.0` | suffix | absent            | defined by other flags | `.`        | `ID.hri`               |
/// | `.1` | absent | added             | absent                 | n/a        | `IDchecksum`           |
/// | `.2` | absent | added             | absent                 | n/a        | chunk(`ID`)            |
/// | `.3` | absent | added             | absent                 | n/a        | chunk(`IDchecksum`)    |
/// | `.`N | reserved | | | | |
/// | A`<` | prefix | absent            | defined by other flags | `A`        | `hri`A`ID`             |
/// | A`^` | prefix | added<sup>*</sup> | defined by other flags | `A`        | `hri`A`IDchecksum`     |
/// | A`>` | suffix | added<sup>*</sup> | defined by other flags | `A`        | `IDchecksum`A`hri`     |
///
/// _<sup>*</sup> added if no mnemonic flags are given_
///
/// ## Mnemonic representation of the checksum
///
/// The presence and position of mnemonic is defined by alternative and sign flags:
///
/// | Flag | HRI    | Checksum          | Mnemonic               | Separators | Example                |
/// |------|--------|-------------------|------------------------|------------|------------------------|
/// | none | -      | defined by HRI flags | absent              | n/a        |                        |
/// | `#`  | -      | -                 | suffix (dashed)        | `#`        | `ID#solo-lemur-wishes` |
/// | `0`  | -      | -                 | prefix (capitalized)   | `0`        | `SoloLemurWishes0ID`   |
/// | `-`  | -      | -                 | prefix (dashes)        | `-`        | `solo-lemur-wishes-ID` |
/// | `+`  | -      | -                 | prefix (underscored)   | `_`        | `solo_lemur_wishes_ID` |

impl<const LEN: usize> Display for Baid58<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
        enum Mnemo {
            None,
            Prefix(MnemonicCase),
            Suffix,
            Mixin,
        }
        #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
        enum Hrp {
            None,
            Prefix(String),
            Suffix(String),
            Ext,
        }

        let mut mnemo = if f.alternate() {
            Mnemo::Suffix
        } else if f.sign_aware_zero_pad() {
            Mnemo::Prefix(MnemonicCase::Pascal)
        } else if f.sign_minus() {
            Mnemo::Prefix(MnemonicCase::Kebab)
        } else if f.sign_plus() {
            Mnemo::Prefix(MnemonicCase::Snake)
        } else {
            Mnemo::None
        };

        let fill = (0..=f.width().unwrap_or_default()).map(|_| f.fill()).collect();
        let hrp = match f.align() {
            None if f.precision() == Some(0) => Hrp::Ext,
            None if f.precision() == Some(1) || f.precision() == Some(3) => {
                mnemo = Mnemo::Mixin;
                Hrp::None
            }
            None => Hrp::None,
            Some(Alignment::Center) if mnemo == Mnemo::None => {
                mnemo = Mnemo::Mixin;
                Hrp::Prefix(fill)
            }
            Some(Alignment::Left) | Some(Alignment::Center) => Hrp::Prefix(fill),
            Some(Alignment::Right) => {
                mnemo = Mnemo::Mixin;
                Hrp::Suffix(fill)
            }
        };

        if let Hrp::Prefix(ref prefix) = hrp {
            f.write_str(self.hri)?;
            f.write_str(prefix)?;
        }

        if let Mnemo::Prefix(prefix) = mnemo {
            f.write_str(&self.clone().mnemonic_with_case(prefix))?;
            match prefix {
                MnemonicCase::Pascal => f.write_str("0")?,
                MnemonicCase::Kebab => f.write_str("-")?,
                MnemonicCase::Snake => f.write_str("_")?,
            }
        }

        let s = if mnemo == Mnemo::Mixin {
            let mut p = self.payload.to_vec();
            p.extend(self.checksum().to_le_bytes());
            p.to_base58()
        } else {
            self.payload.to_base58()
        };
        match (self.chunking, f.precision()) {
            (Some(chunking), Some(2 | 3)) => {
                let mut iter = s.chars();
                for len in chunking.positions {
                    for ch in iter.by_ref().take(*len as usize) {
                        f.write_char(ch)?;
                    }
                    if !iter.as_str().is_empty() {
                        f.write_char(chunking.separator)?;
                    }
                }
                for ch in iter {
                    f.write_char(ch)?;
                }
            }
            _ => {
                f.write_str(&s)?;
            }
        }

        if let Mnemo::Suffix = mnemo {
            write!(f, "#{}", &self.clone().mnemonic_with_case(MnemonicCase::Kebab))?;
        }

        if let Hrp::Suffix(ref suffix) = hrp {
            f.write_str(suffix)?;
            f.write_str(self.hri)?;
        } else if let Hrp::Ext = hrp {
            write!(f, ".{}", self.hri)?;
        }

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Ord, PartialOrd)]
pub enum Baid58ParseError {
    InvalidHri {
        expected: &'static str,
        found: String,
    },
    InvalidLen {
        expected: usize,
        found: usize,
    },
    InvalidMnemonic(String),
    InvalidChecksumLen(usize),
    ChecksumMismatch {
        expected: u32,
        present: u32,
    },
    ValueTooShort(usize),
    NonValueTooLong(usize),
    ValueAbsent(String),
    /// The input contained a character which is not a part of the base58 format.
    InvalidBase58Character(char, usize),
    /// The input had invalid length.
    InvalidBase58Length,
    InvalidChunking,
    Unparsable(String),
}

impl From<FromBase58Error> for Baid58ParseError {
    fn from(value: FromBase58Error) -> Self {
        match value {
            FromBase58Error::InvalidBase58Character(c, pos) => {
                Baid58ParseError::InvalidBase58Character(c, pos)
            }
            FromBase58Error::InvalidBase58Length => Baid58ParseError::InvalidBase58Length,
        }
    }
}

impl Display for Baid58ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Baid58ParseError::InvalidHri { expected, found } => write!(
                f,
                "type requires '{expected}' as a Baid58 human-readable identifier, while \
                 '{found}' was provided"
            ),
            Baid58ParseError::InvalidLen { expected, found } => write!(
                f,
                "type requires {expected} data bytes for aa Baid58 representation, while \
                 '{found}' was provided"
            ),

            Baid58ParseError::ValueTooShort(len) => write!(
                f,
                "Baid58 value must be longer than 8 characters, while only {len} chars were used \
                 for the value"
            ),
            Baid58ParseError::NonValueTooLong(len) => write!(
                f,
                "at least one of non-value components in Baid58 string has length {len} which is \
                 more than allowed 8 characters"
            ),
            Baid58ParseError::ValueAbsent(s) => {
                write!(f, "Baid58 string {s} has no identifiable value component")
            }
            Baid58ParseError::InvalidBase58Character(c, pos) => {
                write!(f, "invalid Base58 character '{c}' at {pos} position in Baid58 value")
            }
            Baid58ParseError::InvalidBase58Length => {
                f.write_str("invalid length of the Base58 encoded value")
            }
            Baid58ParseError::Unparsable(s) => write!(f, "non-parsable Baid58 string '{s}'"),
            Baid58ParseError::InvalidMnemonic(m) => {
                write!(f, "invalid Baid58 mnemonic string '{m}'")
            }
            Baid58ParseError::ChecksumMismatch { expected, present } => {
                write!(f, "invalid Baid58 checksum: expected {expected:#x}, found {present:#x}")
            }
            Baid58ParseError::InvalidChunking => {
                write!(f, "invalid Baid58 chunking")
            }
            Baid58ParseError::InvalidChecksumLen(len) => {
                write!(f, "invalid Baid58 checksum length: expected 4 bytes while found {len}")
            }
        }
    }
}

impl Error for Baid58ParseError {}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Baid58HriError {
    pub expected: &'static str,
    pub found: &'static str,
}

impl Display for Baid58HriError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Baid58HriError { expected, found } = self;
        write!(
            f,
            "type requires '{expected}' as a Baid58 human-readable identifier, while '{found}' \
             was provided"
        )
    }
}

impl Error for Baid58HriError {}

pub trait FromBaid58<const LEN: usize>: ToBaid58<LEN> + From<[u8; LEN]> {
    /// # Format of the string
    ///
    /// The string may contain up to three components: HRI, main value and checksum. Either HRI and
    /// checksum - or both - can be omitted. The components are separated with any non-alphanumeric
    /// printable ASCII character or by `0` (*component separators*); up to two component separators
    /// may be present and they may differ.
    ///
    /// Checksum is always composed of exactly three words, separated by the same non-alphanumeric
    /// printable ASCII character (*checksum separator*). Checksum separator may be the same as
    /// component separator - or may be different. All checksum words must be pure alphabetic ASCII
    /// characters.
    ///
    /// Checksum words and HRI are case-incentive, while main value (as Base58) is case-sensitive.
    /// HRI and may contain non-BASE58 characters 'I' and 'l'. These characters can't be used as any
    /// of the separators.
    ///
    /// HRI and each of the checksum words must be no longer than 8 letters. HRI must be even a
    /// single letter; each of checksum words must contain at least 4 letters. Value component must
    /// be at least 9 characters long.
    ///
    /// HRI, if present, is always the first or the last component.
    ///
    /// The string is parsed using these heuristics. Before processing all repeated
    /// non-alphanumerics are filtered out.
    fn from_baid58_str(s: &str) -> Result<Self, Baid58ParseError> {
        let mut prev: Option<char> = None;
        let mut count = 0;
        // Remove repeated separator characters
        let filtered = s
            .chars()
            .filter_map(|c| {
                let is_separator = !c.is_ascii_alphanumeric() || c == '0';
                if is_separator {
                    count += 1;
                }
                if Some(c) == prev && is_separator {
                    None
                } else {
                    prev = Some(c);
                    prev
                }
            })
            .collect::<String>();

        let mut payload: Option<[u8; LEN]> = None;
        let mut prefix = vec![];
        let mut suffix = vec![];
        let mut cursor = &mut prefix;
        let mut checksum: Option<u32> = None;
        for component in filtered.split(|c: char| !c.is_ascii_alphanumeric() || c == '0') {
            if component.len() > LEN {
                // this is a value
                if payload.is_some() {
                    return Err(Baid58ParseError::NonValueTooLong(component.len()));
                }
                let value = component.from_base58()?;
                let len = value.len();
                match len {
                    x if x == LEN => {}
                    x if x == LEN + 4 => {
                        let mut c = [0u8; 4];
                        c.copy_from_slice(&value[LEN..]);
                        checksum = Some(u32::from_le_bytes(c));
                    }
                    _ => {
                        return Err(Baid58ParseError::InvalidLen {
                            expected: LEN,
                            found: len,
                        })
                    }
                }
                payload = Some([0u8; LEN]);
                if let Some(p) = payload.as_mut() {
                    p.copy_from_slice(&value[..LEN])
                }
                cursor = &mut suffix;
            } else if count == 0 {
                return Err(Baid58ParseError::ValueTooShort(component.len()));
            } else {
                cursor.push(component)
            }
        }

        let mut hri: Option<&str> = None;
        let mut mnemonic = vec![];
        match (prefix.len(), suffix.len()) {
            (0, 0) => {}
            (3 | 4, 0) => {
                hri = prefix.first().copied();
                mnemonic.extend(&prefix[1..])
            }
            (0, 3 | 4) => {
                mnemonic.extend(&suffix[..3]);
                hri = suffix.get(4).copied();
            }
            (2, 0) => {
                hri = Some(prefix[0]);
                mnemonic.push(prefix[1]);
            }
            (1, 0) if prefix[0].len() > HRI_MAX_LEN => {
                mnemonic.extend(prefix);
            }
            (1, 0 | 3..) => {
                hri = prefix.pop();
                mnemonic.extend(suffix);
            }
            (0 | 3.., 1) => {
                mnemonic.extend(prefix);
                hri = suffix.pop();
            }
            _ => return Err(Baid58ParseError::Unparsable(s.to_owned())),
        }

        if matches!(hri, Some(hri) if hri != Self::HRI) {
            return Err(Baid58ParseError::InvalidHri {
                expected: Self::HRI,
                found: hri.unwrap().to_owned(),
            });
        }

        let baid58 = Baid58 {
            hri: Self::HRI,
            chunking: Self::CHUNKING,
            payload: payload.ok_or(Baid58ParseError::ValueAbsent(s.to_owned()))?,
        };

        let mnemonic = match mnemonic.len() {
            0 => String::new(),
            3 => mnemonic.join("-"),
            1 if mnemonic[0].contains('-') => mnemonic[0].to_string(),
            1 if mnemonic[0].contains('_') => mnemonic[0].replace('-', "_"),
            1 => mnemonic[0]
                .chars()
                .flat_map(|c| {
                    if c.is_ascii_uppercase() {
                        vec!['-', c.to_ascii_lowercase()].into_iter()
                    } else {
                        vec![c].into_iter()
                    }
                })
                .collect(),
            _ => return Err(Baid58ParseError::InvalidMnemonic(mnemonic.join("-"))),
        };

        if !mnemonic.is_empty() {
            let mut checksum = Vec::<u8>::with_capacity(4);
            mnemonic::decode(&mnemonic, &mut checksum)
                .map_err(|_| Baid58ParseError::InvalidMnemonic(mnemonic))?;
            if checksum.len() != 4 {
                return Err(Baid58ParseError::InvalidChecksumLen(checksum.len()));
            }
            let checksum = u32::from_le_bytes([checksum[0], checksum[1], checksum[2], checksum[3]]);
            if baid58.checksum() != checksum {
                return Err(Baid58ParseError::ChecksumMismatch {
                    expected: baid58.checksum(),
                    present: checksum,
                });
            }
        }
        if let Some(checksum) = checksum {
            if baid58.checksum() != checksum {
                return Err(Baid58ParseError::ChecksumMismatch {
                    expected: baid58.checksum(),
                    present: checksum,
                });
            }
        }

        Ok(Self::from_baid58(baid58).expect("HRI is checked"))
    }

    fn check_baid58_chunking(mut s: &str, prefix_sep: char, suffix_sep: char) -> bool {
        if let Some(mut pos) = s.chars().position(|c| c == prefix_sep) {
            pos = pos.saturating_add(1);
            if pos >= s.len() {
                return false;
            }
            s = &s[pos..]
        };

        let Some(chunking) = Self::CHUNKING else {
            return false;
        };

        let count =
            s.chars().take_while(|c| *c != suffix_sep).filter(|c| *c == chunking.separator).count();
        if count != chunking.positions.len() {
            return false;
        }
        let mut offset = s
            .chars()
            .take_while(|c| *c != suffix_sep)
            .position(|c| c == prefix_sep)
            .map(|p| p + 1)
            .unwrap_or_default();
        for pos in chunking.positions {
            offset += *pos as usize;
            if s.as_bytes()[offset] != chunking.separator as u8 {
                return false;
            }
            offset = offset.saturating_add(1);
        }
        true
    }

    /// # Safety
    ///
    /// Panics if called on types with `ToBaid58::CHUNKING` set to `None` (which is default
    /// setting).
    fn from_baid58_chunked_str(
        s: &str,
        prefix_sep: char,
        suffix_sep: char,
    ) -> Result<Self, Baid58ParseError> {
        let chunking = Self::CHUNKING
            .expect("FromBaid58::from_baid58_chunked_str must be used only on chunked types");

        if !Self::check_baid58_chunking(s, prefix_sep, suffix_sep) {
            return Err(Baid58ParseError::InvalidChunking);
        }

        let prefix = format!("{}{prefix_sep}", Self::HRI);
        let s = s.trim_start_matches(&prefix);
        let s = prefix.chars().chain(
            s.chars()
                .take_while(|c| *c != suffix_sep)
                .filter(|c| *c != chunking.separator)
                .chain(s.chars().skip_while(|c| *c != suffix_sep)),
        );

        Self::from_baid58_str(&s.collect::<String>())
    }

    /// # Safety
    ///
    /// Panics if called on types with `ToBaid58::CHUNKING` set to `None` (which is default
    /// setting).
    fn from_baid58_maybe_chunked_str(
        s: &str,
        prefix_sep: char,
        suffix_sep: char,
    ) -> Result<Self, Baid58ParseError> {
        if Self::check_baid58_chunking(s, prefix_sep, suffix_sep) {
            Self::from_baid58_chunked_str(s, prefix_sep, suffix_sep)
        } else {
            Self::from_baid58_str(s)
        }
    }

    fn from_baid58(baid: Baid58<LEN>) -> Result<Self, Baid58HriError> {
        if baid.hri != Self::HRI {
            Err(Baid58HriError {
                expected: Self::HRI,
                found: baid.hri,
            })
        } else {
            Ok(Self::from(baid.payload))
        }
    }
}

pub trait ToBaid58<const LEN: usize> {
    const HRI: &'static str;
    const CHUNKING: Option<Chunking> = None;
    // TODO: Uncomment once generic_const_exprs is out
    // const LEN: usize;

    fn to_baid58_payload(&self) -> [u8; LEN];
    fn to_baid58(&self) -> Baid58<LEN> {
        Baid58::new(Self::HRI, self.to_baid58_payload(), Self::CHUNKING)
    }
    fn to_baid58_string(&self) -> String { self.to_baid58().to_string() }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    struct Id([u8; 32]);

    impl Id {
        pub fn new(s: &str) -> Id {
            let hash = blake3::Hasher::new().update(s.as_bytes()).finalize();
            Id(*hash.as_bytes())
        }
    }

    impl From<[u8; 32]> for Id {
        fn from(value: [u8; 32]) -> Self { Id(value) }
    }

    impl ToBaid58<32> for Id {
        const HRI: &'static str = "nym";
        const CHUNKING: Option<Chunking> = CHUNKING_32;
        fn to_baid58_payload(&self) -> [u8; 32] { self.0 }
    }
    impl FromBaid58<32> for Id {}

    impl Display for Id {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let mut baid = self.to_baid58();
            match f.precision() {
                Some(2) => {}
                Some(3) => {
                    baid.chunking.as_mut().map(|c| c.positions = &CHUNK_POSITIONS_32CHECKSUM);
                }
                _ => baid.chunking = None,
            }
            Display::fmt(&baid, f)
        }
    }

    impl FromStr for Id {
        type Err = Baid58ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Id::from_baid58_maybe_chunked_str(&s, ':', '#')
        }
    }

    #[test]
    #[should_panic]
    fn invalid_chunking() {
        #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
        struct Id([u8; 32]);
        impl From<[u8; 32]> for Id {
            fn from(value: [u8; 32]) -> Self { Id(value) }
        }
        impl ToBaid58<32> for Id {
            const HRI: &'static str = "id";
            const CHUNKING: Option<Chunking> = Some(Chunking::new(&[7, 9, 9, 9, 9, 9], '-'));
            fn to_baid58_payload(&self) -> [u8; 32] { self.0 }
        }
        format!("{:.2}", Id::default().to_baid58());
    }

    #[test]
    fn display() {
        let id = Id::new("some information");

        assert_eq!(&format!("{id}"), "FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs");

        assert_eq!(&format!("{id:.0}"), "FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs.id");
        assert_eq!(&format!("{id:.1}"), "2dzcCoX9c65gi1GoJ1LFzb5FcQ9pAc8o3Pj8TpcH2mkAdMLCpP");
        assert_eq!(&format!("{id:.2}"), "FWyisK-GdBG31dd-iNaUjnHi-6tW8eYvn-VW3T4zWt-LhRDHs");
        assert_eq!(&format!("{id:.3}"), "2dzcCoX-9c65gi1Go-J1LFzb5Fc-Q9pAc8o3P-j8TpcH2mk-AdMLCpP");

        assert_eq!(&format!("{id::<}"), "id:FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs");
        assert_eq!(&format!("{id::^}"), "id:2dzcCoX9c65gi1GoJ1LFzb5FcQ9pAc8o3Pj8TpcH2mkAdMLCpP");

        assert_eq!(
            &format!("{id:#}"),
            "FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs#escape-cadet-swim"
        );
        assert_eq!(
            &format!("{id::^#}"),
            "id:FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs#escape-cadet-swim"
        );
        assert_eq!(
            &format!("{id:-.0}"),
            "escape-cadet-swim-FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs.id"
        );
        assert_eq!(
            &format!("{id:<0}"),
            "id EscapeCadetSwim0FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs"
        );
        assert_eq!(
            &format!("{id:_<+}"),
            "id_escape_cadet_swim_FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs"
        );
    }

    #[test]
    fn from_str() {
        let id = Id::new("some information");
        assert_eq!(Id::from_str("FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs").unwrap(), id);

        assert_eq!(
            Id::from_str("id:FWyisK-GdBG31dd-iNaUjnHi-6tW8eYvn-VW3T4zWt-LhRDHs").unwrap(),
            id
        );

        assert_eq!(Id::from_str("2dzcCoX9c65gi1GoJ1LFzb5FcQ9pAc8o3Pj8TpcH2mkAdMLCpP").unwrap(), id);
        assert_eq!(
            Id::from_str("id:2dzcCoX9c65gi1GoJ1LFzb5FcQ9pAc8o3Pj8TpcH2mkAdMLCpP").unwrap(),
            id
        );

        assert_eq!(
            Id::from_str("FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs#escape-cadet-swim").unwrap(),
            id
        );
        assert_eq!(Id::from_str("FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs.id").unwrap(), id);
        assert_eq!(
            Id::from_str("id:FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs#escape-cadet-swim")
                .unwrap(),
            id
        );
        assert_eq!(
            Id::from_str("id:FWyisK-GdBG31dd-iNaUjnHi-6tW8eYvn-VW3T4zWt-LhRDHs#escape-cadet-swim")
                .unwrap(),
            id
        );
        assert_eq!(
            Id::from_str("escape-cadet-swim-FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs.id")
                .unwrap(),
            id
        );
        assert_eq!(
            Id::from_str("EscapeCadetSwim0FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs").unwrap(),
            id
        );
        assert_eq!(
            Id::from_str("id EscapeCadetSwim0FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs")
                .unwrap(),
            id
        );
        assert_eq!(
            Id::from_str("id_escape_cadet_swim_FWyisKGdBG31ddiNaUjnHi6tW8eYvnVW3T4zWtLhRDHs")
                .unwrap(),
            id
        );
    }

    #[test]
    fn attack() {
        let mut handles = vec![];
        for x in 0..24 {
            handles.push(std::thread::spawn(move || {
                for salt in 0..0x10_0000 {
                    let salt = salt * x;
                    let id = Id::new(&format!(
                        "Dr Maxim Orlovsky, LNP/BP Standards Association. Salt {salt}",
                    ))
                    .to_baid58();
                    let mnemo = id.mnemonic();
                    if mnemo.contains("atomic") && mnemo.contains("nuclear") {
                        panic!("{salt}: {id:<-.2}");
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().ok();
        }
    }
}

// Two hashes, 16 bits:
// 0xce6 + 0xee4 + 0x1ad7 + 0x169a + 0x1b15 + 0x1634 + 0x3861 + 0x3d1a + 0x3bf3 + 0x50c3 + 0x7dcd +
// 0xab0c + 0xb58f + 0xac76 + 0xea00 + 0xcfdd + 0x1174e + 0x11a8a + 0x119f7 + 0x1a08e + 0x1e0e8 +
// 0x1d4dd + 0x2e9bc + 0x32316
// Avg: 0xDA2E

// One hash, 16 bits:
// 0x399 + 0x907 + 0x10d4 + 0x1924 + 0x41ea + 0x670f + 0x7651 + 0x704c + 0x5e14 + 0x69f6 + 0x6bf6 +
// 0xbdb4 + 0xa18d + 0xa2cb + 0xe189 + 0x12c3b + 0x1840a + 0x1aaf3 + 0x1b9af + 0x191f4 + 0x1bec5 +
// 0x2c04b + 0x401d7 + 0x5ab15
// Avg: 0x1275B

// Two hashes, 24 bits:
// 0x797b3 + 0x9dff5 + 0x1b32e3 + 0x4839f8 + 0x5a60e1 + 0x8c114d + 0x99d3c2 + 0x9c253f + 0xaeb79f +
// 0xb1ad32 + 0xb4b454 + 0xc04c86 + 0xcb45ae + 0xd02170 + 0xda76ca + 0xe2caca + 0x1051a90 +
// 0x1067210 + 0x11b4e06 + 0x123e239 + 0x12dfa39 + 0x14bfc08 + 0x15e84d4 + 0x175c9a0 + 0x189f99b +
// 0x1942417 + 0x1b56b73 + 0x1b3ae84 + 0x1be9dbd + 0x1e78d54 + 0x1fc9fd0 + 0x201a7d2 + 0x202f210 +
// 0x20a0c84 + 0x21beb72 + 0x223e1c6 + 0x2377a9d + 0x23d0d29 + 0x242387d + 0x24733c9 + 0x253bf88 +
// 0x26922d0 + 0x269a164 + 0x2685278 + 0x26724cc + 0x27d41a4 + 0x27aa27a + 0x28349a9 + 0x288692e +
// 0x29b49c8 + 0x2a8ae22 + 0x2a753ac + 0x2aebd1e + 0x2a74338 + 0x2ba5730 + 0x2c73e8b + 0x2dbd2f3 +
// 0x2d27825 + 0x2df7c4e + 0x313bb3c + 0x308b47d + 0x312ea5a + 0x3199629 + 0x31baa54 + 0x325d602 +
// 0x3372ed4 + 0x339431f + 0x33e2bf9 + 0x3851677 + 0x38b882b + 0x3d7e406
// 0x8A3A95FF / 71 = 0x1'F2'67'12

// One hash, 24 bits:
// 0x10ebbf + 0x24c0d7 + 0x3482eb + 0x42a67d + 0x5267c9 + 0x5e3e35 + 0x61dfc0 + 0x7e00d9 + 0x73f791
// + 0x7fff0f + 0x98b23e + 0xa6b60c + 0xb8e6ee + 0xaea505 + 0xe87274 + 0x14ba442 + 0x1830eb5 +
// 0x1ad4fc6 + 0x1c60c47 + 0x2455ecc + 0x2d1ee9c + 0x2d69ebc + 0x35fb073 + 0x394e680
// 0x1BE54C01 / 24 = 0x1'29'8D'D5
