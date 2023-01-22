# Baid58: a easy-to-check Base58 encoding for identities

![Build](https://github.com/UBIDECO/rust-baid58/workflows/Build/badge.svg)
![Tests](https://github.com/UBIDECO/rust-baid58/workflows/Tests/badge.svg)
![Lints](https://github.com/UBIDECO/rust-baid58/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/UBIDECO/rust-baid58/branch/master/graph/badge.svg)](https://codecov.io/gh/UBIDECO/rust-baid58)

[![crates.io](https://img.shields.io/crates/v/baid58)](https://crates.io/crates/baid58)
[![Docs](https://docs.rs/baid58/badge.svg)](https://docs.rs/cyphernet)
[![Apache-2 licensed](https://img.shields.io/crates/l/baid58)](./LICENSE)

## TL;DR

_**Baid58 is a Base58 equipped with an optional checksum (which is easy to
see and verify) and human-readable information about the value.**_

## Overview

A lot of [binary-to-text encoding formats](t2b) exists today, which are designed
for a different specific cases. Why another one? Well, since we have a need to
encode short-length unique identifiers - like file or data structure hashes,
cryptographic public keys, digital identities and certificates etc..

`Baid58` is a format for representing unique identities based on Base58 encoding
("baid" is a combination of "base" and "identity"). It is designed to match the
following criteria:
* be as short as possible;
* but still copyable with a single mouse click;
* work well with URLs;
* maybe used as a file or directory name;
* may be equipped with easy-to-visually verify checksum information when needed;
* may contain simple human-readable prefix explaining the meaning of the value;
* rely on an existing widespread binary-to-text encoding.

We have chosen Base58 as most concise and widespread encoding which can be 
copied with a single click. We designed a way how it can be stuffed with prefix
and suffix information to represent a human-readable identifier (HRI) and
checksum in a different ways depending on a use case, like:

- **file name**:
  `tommy-fuel-pagoda-7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt.stl`
- **single-click address**:
  `stlTommyFuelPagoda07EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt`
- **visually clear address**:
  `stl_tommy_fuel_pagoda_7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt`
- **URI or a part of URL**:
  `stl:7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt#tommy_fuel_pagoda`

As you see, a `Baid58` encoded value is composed of the following components:
* The actual *value* encoded with a Base58 encoding (using bitcoin flavour of 
  it);
* Optional *human-readable identifier (HRI)* which can prefix or follow the main 
  value;
* Optional checksum *mnemonic*, representing 32 least-significant bits of BLAKE3
  hash of the value created using HRI as a hashing key. The mnemonic is created
  using [tothink.com] dictionary and consists of three easy-to-distinguish 
  words.


## Why not...

### Why not Base64

Since it contains characters which can't be used in URLs, file names and the
encoded string can't be always selected with a single-click.

### Why not Base58

Baid58 is in fact Base58 equipped with an optional checksum (which is easy to
see and verify) and human-readable information about the value.

### Why not Bech32

First, Bech32 strings are usually too long, while have no real advantages:
* it is said they do not contain characters which can be confused - but this is
  not a problem when a checksum is used and checked both visually and by a
  computer, while ...
* bech32 "checksum" is not visually distinguishable and most people even do not
  know where it is. In the result one may craft a string which will be still
  visually similar even when it has a correct and different checksum - and both
  humans and computers will miss the attack.
* bech32 is stuffed with ECC, but if the string is broken we probably shouldn't
  use it at all (instead of trying to automatically correct errors). And we can
  see broken values when the mnemonic checksum doesn't match;
* it is said Bech32 can result in shorter QRs, but it is not true: for instance
  QR code for both Base58-encoded 160-bit bitcoin P2SH and Bech32-encoded 
  160-bit P2WPK address have exactly the same size - if a user hasn't forgotten
  to uppercase the address value - or Bech32 QR code is larger if the uppercase
  was not maid!

As a result, we are getting longer strings to read, non-standard wierd 
encoding, false feel of safety - and no advantages over Base58, which only needs
efficient and clearly-distinguished checksum and value type information - and
this is exactly what Baid58 adds.

### Why not multiformats


## Using crate

Both HRI part and mnemonic checksum may be omitted - in this case we have just
an unmodified `Base58` string. Alternatively, they can be formatted with this 
crate using rich functionality of rust display formatting language in the 
following ways:
- `#` - add kebab-case mnemonic as a suffix separated with `#`;
- `0` - prefix with capitalized mnemonic separated with zero from the main code;
- `-` - prefix with dash-separated mnemonic;
- `+` - prefix with underscore-separated mnemonic;
- `.` - suffix with HRI in form of a file extension;
- `<` - prefix with HRI separating from the value using fill character(s). 
  Requires mnemonic prefix flag or defaults it to `0`.
- `^` - prefix with HRP without mnemonic, using fill character as separator - or
  defaulting to `_^` otherwise;
- `>` - suffix with HRI, using fill character as a separator

If width is given, it is used to place multiple fill characters between the
value and HRI.

Example formatting strings from the above:
- **file name**: `{:-.1}` ->
  `tommy-fuel-pagoda-7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt.stl`
- **single-click address**: `{:<0}` ->
  `stlTommyFuelPagoda07EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt`
- **visually clear address**: `{:_<+}` ->
  `stl_tommy_fuel_pagoda_7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt`
- **URI or a part of URL**: `{::^#}` ->
  `stl:7EnUZgFtu28sWqqH3womkTopXCkgAGsCLvLnYvNcPLRt#tommy_fuel_pagoda`


[b2t]: https://en.wikipedia.org/wiki/Binary-to-text_encoding
[tothink.com]: http://web.archive.org/web/20101031205747/http://www.tothink.com/mnemonic/
