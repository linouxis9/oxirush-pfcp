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

//! The values of a row that is a list: one in place, more in a vector.

use alloc::vec::Vec;
use core::ops::Deref;

use crate::octets::IntoOwned;

/// The values of a row that is a list. Most lists of a message have one value, which it
/// keeps in place: only a second one allocates. It dereferences to a slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List<T>(Repr<T>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Repr<T> {
    Empty,
    One(T),
    Many(Vec<T>),
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self(Repr::Empty)
    }
}

impl<T> List<T> {
    /// No value.
    pub const fn new() -> Self {
        Self(Repr::Empty)
    }

    /// Add a value at the end.
    #[inline]
    pub fn push(&mut self, value: T) {
        match &mut self.0 {
            Repr::Empty => self.0 = Repr::One(value),
            Repr::Many(values) => values.push(value),
            Repr::One(_) => {
                let Repr::One(first) = core::mem::replace(&mut self.0, Repr::Empty) else { unreachable!() };
                let mut values = Vec::with_capacity(4);
                values.push(first);
                values.push(value);
                self.0 = Repr::Many(values);
            }
        }
    }

    /// Room for `more` values: a vector from two.
    pub fn reserve_exact(&mut self, more: usize) {
        if let Repr::Many(values) = &mut self.0 {
            values.reserve_exact(more);
        } else if self.len() + more > 1 {
            let mut values = Vec::with_capacity(self.len() + more);
            if let Repr::One(first) = core::mem::replace(&mut self.0, Repr::Empty) {
                values.push(first);
            }
            self.0 = Repr::Many(values);
        }
    }

    /// The values, as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        match &self.0 {
            Repr::Empty => &[],
            Repr::One(value) => core::slice::from_ref(value),
            Repr::Many(values) => values,
        }
    }

    /// The values, to change.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match &mut self.0 {
            Repr::Empty => &mut [],
            Repr::One(value) => core::slice::from_mut(value),
            Repr::Many(values) => values,
        }
    }

    /// The values, as a vector.
    pub fn into_vec(self) -> Vec<T> {
        match self.0 {
            Repr::Empty => Vec::new(),
            Repr::One(value) => alloc::vec![value],
            Repr::Many(values) => values,
        }
    }
}

impl<T> Deref for List<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> From<Vec<T>> for List<T> {
    fn from(mut values: Vec<T>) -> Self {
        match values.len() {
            0 => Self::new(),
            1 => Self(Repr::One(values.pop().unwrap_or_else(|| unreachable!()))),
            _ => Self(Repr::Many(values)),
        }
    }
}

impl<T: IntoOwned> IntoOwned for List<T> {
    type Owned = List<T::Owned>;
    fn into_owned(self) -> Self::Owned {
        List(match self.0 {
            Repr::Empty => Repr::Empty,
            Repr::One(value) => Repr::One(value.into_owned()),
            Repr::Many(values) => Repr::Many(values.into_owned()),
        })
    }
}

impl<'l, T> IntoIterator for &'l List<T> {
    type Item = &'l T;
    type IntoIter = core::slice::Iter<'l, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}
