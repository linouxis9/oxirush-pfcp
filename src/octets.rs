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

//! The octets of a value: kept in place for a short one, on the heap for a long one.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// How many octets an [`Octets`] holds without an allocation.
const INLINE: usize = 22;

/// A string of octets of a value. It dereferences to `[u8]`.
///
/// A value holds its octets: up to 22 in place, more on the heap at their exact length.
#[derive(Clone)]
pub struct Octets(Repr);

#[derive(Clone)]
enum Repr {
    /// No octets: what most values' later octets are, built and dropped for nothing.
    Empty,
    Inline {
        length: u8,
        octets: [u8; INLINE],
    },
    Heap(Box<[u8]>),
}

impl Octets {
    /// No octets.
    pub const fn new() -> Self {
        Self(Repr::Empty)
    }

    /// A copy of `octets`.
    pub fn copied(octets: &[u8]) -> Self {
        match octets.len() {
            0 => Self(Repr::Empty),
            length @ 1..=INLINE => {
                let mut inline = [0; INLINE];
                inline[..length].copy_from_slice(octets);
                Self(Repr::Inline {
                    length: length as u8,
                    octets: inline,
                })
            }
            _ => Self(Repr::Heap(octets.into())),
        }
    }

    /// The octets as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            Repr::Empty => &[],
            Repr::Inline { length, octets } => &octets[..usize::from(*length)],
            Repr::Heap(octets) => octets,
        }
    }
}

impl Default for Octets {
    fn default() -> Self {
        Self(Repr::Empty)
    }
}

impl Deref for Octets {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Octets {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Octets {}

impl fmt::Debug for Octets {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for octet in self.as_slice() {
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

impl From<Vec<u8>> for Octets {
    fn from(octets: Vec<u8>) -> Self {
        match octets.len() {
            0..=INLINE => Self::copied(&octets),
            _ => Self(Repr::Heap(octets.into_boxed_slice())),
        }
    }
}

impl From<&[u8]> for Octets {
    fn from(octets: &[u8]) -> Self {
        Self::copied(octets)
    }
}

impl<const N: usize> From<[u8; N]> for Octets {
    fn from(octets: [u8; N]) -> Self {
        Self::copied(&octets)
    }
}
