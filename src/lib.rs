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
use std::fmt::{Alignment, Display, Formatter};

use base58::{FromBase58, FromBase58Error, ToBase58};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum MnemonicCase {
    Pascal,
    Kebab,
    Snake,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid58<const LEN: usize> {
    hri: &'static str,
    payload: [u8; LEN],
}

impl<const LEN: usize> Baid58<LEN> {
    pub fn with(hri: &'static str, payload: [u8; LEN]) -> Self { Self { hri, payload } }

    pub const fn human_identifier(&self) -> &'static str { self.hri }

    pub fn checksum(&self) -> u32 {
        let key = blake3::Hasher::new().update(self.hri.as_bytes()).finalize();
        let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
        hasher.update(&self.payload);
        let hash = *hasher.finalize().as_bytes();
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
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
/// - no flags: do not add HRI and mnemonic
/// - `#` - suffix with kebab-case mnemonic, separated with `#` from the main value;
/// - `0` - prefix with capitalized mnemonic separated with zero from the main value;
/// - `-` - prefix with dashed separated mnemonic;
/// - `+` - prefix with underscore separated mnemonic;
/// - `.` - suffix with HRI representing it as a file extension;
/// - `<` - prefix with HRI; requires mnemonic prefix flag or defaults it to `0` and separates from
///   the mnemonic using fill character and width;
/// - `^` - prefix with HRI without mnemonic, using fill character as separator or defaulting to
///   `_^` otherwise, width value implies number of character replications;
/// - `>` - suffix with HRI, using fill character as a separator. If width is given, use multiple
///   fill characters up to a width.
impl<const LEN: usize> Display for Baid58<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
        enum Mnemo {
            None,
            Prefix(MnemonicCase),
            Suffix,
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
            None if f.precision().is_some() => Hrp::Ext,
            None => Hrp::None,
            Some(Alignment::Left) if mnemo == Mnemo::None => {
                mnemo = Mnemo::Prefix(MnemonicCase::Pascal);
                Hrp::Prefix(fill)
            }
            Some(Alignment::Left) | Some(Alignment::Center) => Hrp::Prefix(fill),
            Some(Alignment::Right) => Hrp::Suffix(fill),
        };

        if let Hrp::Prefix(ref prefix) = hrp {
            f.write_str(self.hri)?;
            f.write_str(prefix)?;
        }

        if let Mnemo::Prefix(prefix) = mnemo {
            f.write_str(&self.mnemonic_with_case(prefix))?;
            match prefix {
                MnemonicCase::Pascal => f.write_str("0")?,
                MnemonicCase::Kebab => f.write_str("-")?,
                MnemonicCase::Snake => f.write_str("_")?,
            }
        }

        f.write_str(&self.payload.to_base58())?;

        if let Mnemo::Suffix = mnemo {
            write!(f, "#{}", &self.mnemonic_with_case(MnemonicCase::Kebab))?;
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

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Baid58ParseError {
    InvalidHri {
        expected: &'static str,
        found: String,
    },
    InvalidLen {
        expected: usize,
        found: usize,
    },
    ValueTooShort(usize),
    NonValueTooLong(usize),
    ValueAbsent(String),
    /// The input contained a character which is not a part of the base58 format.
    InvalidBase58Character(char, usize),
    /// The input had invalid length.
    InvalidBase58Length,
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
        let filtered = s
            .chars()
            .filter_map(|c| {
                let non_alpha = !c.is_ascii_alphanumeric();
                if non_alpha || c == '0' {
                    count += 1;
                }
                if Some(c) == prev && non_alpha {
                    None
                } else {
                    prev = Some(c);
                    prev
                }
            })
            .collect::<String>();

        let mut hri: Option<&str> = None;
        let mut payload: Option<[u8; LEN]> = None;
        let mut mnemonic = vec![];
        for (index, component) in
            filtered.split(|c: char| !c.is_ascii_alphanumeric() || c == '0').enumerate()
        {
            if component.len() > 8 {
                // this is a value
                if payload.is_some() {
                    return Err(Baid58ParseError::NonValueTooLong(component.len()));
                }
                let value = component.from_base58()?;
                let len = value.len();
                if len != LEN {
                    return Err(Baid58ParseError::InvalidLen {
                        expected: LEN,
                        found: len,
                    });
                }
                payload = Some([0u8; LEN]);
                payload.as_mut().map(|p| p.copy_from_slice(&value[..]));
            } else if count == 1 {
                return Err(Baid58ParseError::ValueTooShort(component.len()));
            } else if (index == 0 || index == count - 1) && count > 2 && hri.is_none() {
                hri = Some(component);
            } else {
                mnemonic.push(component);
            }
        }

        if matches!(hri, Some(hri) if hri != Self::HRI) {
            return Err(Baid58ParseError::InvalidHri {
                expected: Self::HRI,
                found: hri.unwrap().to_owned(),
            });
        }

        // TODO: Check checksum

        Ok(Self::from_baid58(Baid58 {
            hri: Self::HRI,
            payload: payload.ok_or(Baid58ParseError::ValueAbsent(s.to_owned()))?,
        })
        .expect("HRI is checked"))
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
    // TODO: Uncomment once generic_const_exprs is out
    // const LEN: usize;

    fn to_baid58_payload(&self) -> [u8; LEN];
    fn to_baid58(&self) -> Baid58<LEN> { Baid58::with(Self::HRI, self.to_baid58_payload()) }
    fn to_baid58_string(&self) -> String { self.to_baid58().to_string() }
}
