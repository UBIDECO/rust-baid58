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

use std::fmt;
use std::fmt::{Alignment, Display, Formatter};

use base58::ToBase58;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum MnemonicCase {
    Pascal,
    Kebab,
    Snake,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid58<const LEN: usize> {
    hrp: &'static str,
    payload: [u8; LEN],
    checksum: u32,
}

impl<const LEN: usize> Baid58<LEN> {
    pub fn with(hrp: &'static str, payload: [u8; LEN]) -> Self {
        let key = blake3::Hasher::new().update(hrp.as_bytes()).finalize();
        let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
        hasher.update(&payload);
        let hash = *hasher.finalize().as_bytes();
        let checksum = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        Self {
            hrp,
            payload,
            checksum,
        }
    }

    pub fn checksum(&self) -> u32 { self.checksum }

    pub fn mnemonic(&self) -> String { self.mnemonic_with_case(MnemonicCase::Kebab) }

    pub fn mnemonic_with_case(&self, case: MnemonicCase) -> String {
        let mn = mnemonic::to_string(self.checksum.to_le_bytes());
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
            f.write_str(self.hrp)?;
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
            f.write_str(self.hrp)?;
        } else if let Hrp::Ext = hrp {
            write!(f, ".{}", self.hrp)?;
        }

        Ok(())
    }
}

pub trait ToBaid58<const LEN: usize>: Display /* TODO: + FromStr */ {
    const HRP: &'static str;
    // TODO: Uncomment once generic_const_exprs is out
    // const LEN: usize;

    fn to_baid58_payload(&self) -> [u8; LEN];
    fn to_baid58(&self) -> Baid58<LEN> { Baid58::with(Self::HRP, self.to_baid58_payload()) }
}
