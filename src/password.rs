// Copyright 2020 Ledger SAS
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

/// A basic class to store strings are fixed-size arrays.
/// Storing null characters is not allowed (null is reserved to detect the
/// end of the string). The stored string is not null terminated in the case
/// all the array is used to store characters.
#[derive(Clone, Copy)]
pub struct ArrayString<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> ArrayString<N> {
    /// Create an empty string
    pub const fn new() -> ArrayString<N> {
        ArrayString { bytes: [0; N] }
    }

    /// Set the string from an array of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Array of bytes. Max size is N. The string must not have null
    ///   bytes, but the last bytes of the array can be null (zero padding).
    pub fn set_from_bytes(&mut self, bytes: &[u8]) {
        let mut len = bytes.len();
        while (len > 0) && (bytes[len - 1]) == 0 {
            len -= 1;
        }
        assert!(len <= N);
        self.bytes[..len].copy_from_slice(&bytes[..len]);
        for i in len..N {
            self.bytes[i] = 0;
        }
    }

    /// Returns an ArrayString initialized from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Array of bytes. Max size is N. Must not have null bytes.
    pub fn from_bytes(bytes: &[u8]) -> ArrayString<N> {
        let mut result = ArrayString::new();
        result.set_from_bytes(bytes);
        result
    }

    /// Number of bytes in the string.
    pub fn len(&self) -> usize {
        let mut size = N;
        while (size > 0) && (self.bytes[size - 1] == 0) {
            size -= 1;
        }
        size
    }

    /// Return the bytes, non-mutable!
    pub fn bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Return the bytes as a str
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len()]).unwrap()
    }
}

impl<const N: usize> core::cmp::PartialEq for ArrayString<N> {
    fn eq(&self, other: &Self) -> bool {
        let len = self.len();
        if other.len() != len {
            return false;
        }
        self.bytes[..len] == other.bytes[..len]
    }
}

impl<const N: usize> Eq for ArrayString<N> {}

/// Storage for a password.
///
/// This is intended to be stored in the Flash memory:
/// - members have fixed size
/// - total size of PasswordItem should be a multiple of Flash page size (here
///   64).
///
/// As name and size are fixed arrays, we consider stored strings are padded
/// with zeros. This is not null terminated, and UTF8 is allowed.
#[derive(Clone, Copy)]
pub struct PasswordItem {
    pub name: ArrayString<32>,
    pub pass: ArrayString<32>,
}

impl PasswordItem {
    pub const fn new() -> PasswordItem {
        PasswordItem {
            name: ArrayString::new(),
            pass: ArrayString::new(),
        }
    }
}
