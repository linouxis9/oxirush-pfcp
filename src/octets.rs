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

//! The octets of a value: kept in place for a short one, on the heap for a long one, or
//! borrowed from the octets that a message was decoded from.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// How many octets an [`Octets`] holds without an allocation.
const INLINE: usize = 22;

/// A string of octets of a value. It dereferences to `[u8]`.
///
/// A decoded value borrows its octets from the message (`pfcp_borrowed`) or copies them
/// (otherwise): up to 22 octets in place, more on the heap at their exact length. A
/// built value owns them. [`into_owned`](Self::into_owned) gives a value that borrows
/// nothing.
#[derive(Clone)]
pub struct Octets<'a>(Repr<'a>);

#[derive(Clone)]
enum Repr<'a> {
    Inline { length: u8, octets: [u8; INLINE] },
    Heap(Box<[u8]>),
    #[cfg_attr(not(pfcp_borrowed), allow(dead_code))]
    Borrowed(&'a [u8]),
}

impl<'a> Octets<'a> {
    /// No octets.
    pub const fn new() -> Self {
        Self(Repr::Inline { length: 0, octets: [0; INLINE] })
    }

    /// A copy of `octets`.
    pub fn copied(octets: &[u8]) -> Self {
        match octets.len() {
            length @ 0..=INLINE => {
                let mut inline = [0; INLINE];
                inline[..length].copy_from_slice(octets);
                Self(Repr::Inline { length: length as u8, octets: inline })
            }
            _ => Self(Repr::Heap(octets.into())),
        }
    }

    /// The octets of a value of a decoded message: borrowed, or copied.
    #[inline]
    pub(crate) fn wire(octets: &'a [u8]) -> Self {
        #[cfg(pfcp_borrowed)]
        {
            Self(Repr::Borrowed(octets))
        }
        #[cfg(not(pfcp_borrowed))]
        {
            Self::copied(octets)
        }
    }

    /// The octets as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline { length, octets } => &octets[..usize::from(*length)],
            Repr::Heap(octets) => octets,
            Repr::Borrowed(octets) => octets,
        }
    }

    /// The same octets, borrowing nothing.
    pub fn into_owned(self) -> Octets<'static> {
        Octets(match self.0 {
            Repr::Inline { length, octets } => Repr::Inline { length, octets },
            Repr::Heap(octets) => Repr::Heap(octets),
            Repr::Borrowed(octets) => return Octets::copied(octets),
        })
    }

    /// Whether the octets are borrowed.
    pub fn is_borrowed(&self) -> bool {
        matches!(self.0, Repr::Borrowed(_))
    }
}

impl Default for Octets<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Octets<'_> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Octets<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Octets<'_> {}

impl fmt::Debug for Octets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for octet in self.as_slice() {
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

impl From<Vec<u8>> for Octets<'_> {
    fn from(octets: Vec<u8>) -> Self {
        match octets.len() {
            0..=INLINE => Self::copied(&octets),
            _ => Self(Repr::Heap(octets.into_boxed_slice())),
        }
    }
}

impl From<&[u8]> for Octets<'_> {
    fn from(octets: &[u8]) -> Self {
        Self::copied(octets)
    }
}

impl<const N: usize> From<[u8; N]> for Octets<'_> {
    fn from(octets: [u8; N]) -> Self {
        Self::copied(&octets)
    }
}

/// A value that borrows from a decoded message, and its copy that borrows nothing.
pub trait IntoOwned {
    /// The type that borrows nothing.
    type Owned;
    /// The value, borrowing nothing.
    fn into_owned(self) -> Self::Owned;
}

impl<'a> IntoOwned for Octets<'a> {
    type Owned = Octets<'static>;
    fn into_owned(self) -> Octets<'static> {
        Octets::into_owned(self)
    }
}

impl<T: IntoOwned> IntoOwned for Option<T> {
    type Owned = Option<T::Owned>;
    fn into_owned(self) -> Self::Owned {
        self.map(IntoOwned::into_owned)
    }
}

impl<T: IntoOwned> IntoOwned for Vec<T> {
    type Owned = Vec<T::Owned>;
    fn into_owned(self) -> Self::Owned {
        // Of the same layout, the vector is reused in place.
        self.into_iter().map(IntoOwned::into_owned).collect()
    }
}
