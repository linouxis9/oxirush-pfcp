/*
   OxiRush
   Copyright 2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! The octets read by this crate and by rs-pfcp 0.5.0, a codec of PFCP written apart from
//! it, compared as [`readings::compare`] says: the message that each decodes or refuses,
//! its header, the IEs at every level and the values of ten IE types. A difference is a
//! fault of either, or a reading of TS 29.244 that the two do not share, which the target
//! names (`readings::READINGS`).
#![no_main]

mod readings;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| readings::compare(octets));
