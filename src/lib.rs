// Copyright (c) 2014 Michael Woerister
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! This package implements a global string table, allowing to unique strings
//! in a threadsafe way.

#![feature(default_type_params)]

use std::collections::HashMap;
use std::sync::{Once, ONCE_INIT, Mutex, MutexGuard};
use std::sync::atomics::{AtomicUint, SeqCst};
use std::rt::heap;
use std::mem;
use std::ptr;

//=-------------------------------------------------------------------------------------------------
// StringTableEntry
//=-------------------------------------------------------------------------------------------------

#[repr(C)]
struct StringTableEntry {
    ref_count: AtomicUint,
    length: u16,
    // immediately followed by the string bytes itself, not null-terminated
}

fn get_string_table_entry_header_size() -> uint {
    mem::size_of::<AtomicUint>() + mem::size_of::<u16>()
}

fn get_ptr_to_str_data(e: *mut StringTableEntry) -> *mut u8 {
    let as_bytes = e as *mut u8;
    debug_assert!(as_bytes as uint == e as uint);
    unsafe { as_bytes.offset(get_string_table_entry_header_size() as int) }
}

fn get_string_table_entry_allocation_size_for(s: &str) -> uint {
     get_string_table_entry_header_size() + s.as_bytes().len()
}

fn allocate_string_table_entry_for(s: &str) -> *mut StringTableEntry {
    assert!(s.len() < ::std::u16::MAX as uint);

    let align = mem::align_of::<StringTableEntry>();
    // Make sure that our pointer tagging assumptions are valid
    debug_assert!(align >= 2);
    debug_assert!(s.len() >= mem::size_of::<uint>());

    let size = get_string_table_entry_allocation_size_for(s);

    unsafe {
        let ptr = heap::allocate(size, align) as *mut StringTableEntry;
        // This has to hold if we want to use pointer tagging
        debug_assert!(ptr as uint % 2 == 0);

        // Init the header fields
        ptr::write(&mut (*ptr).ref_count, AtomicUint::new(1));
        ptr::write(&mut (*ptr).length, s.len() as u16);

        // Copy the string data
        ::std::slice::raw::mut_buf_as_slice(get_ptr_to_str_data(ptr), s.as_bytes().len(), |slice| {
             ::std::slice::bytes::copy_memory(slice, s.as_bytes());
        });

        // Assert that we have a valid entry now
        debug_assert!(string_table_entry_to_str_slice(ptr) == s);

        return ptr;
    }
}

fn deallocate_string_table_entry(e: *mut StringTableEntry) {
    let align = mem::align_of::<StringTableEntry>();

    unsafe {
        let size = get_string_table_entry_allocation_size_for(string_table_entry_to_str_slice(e));
        heap::deallocate(e as *mut u8, size, align);
    }
}

unsafe fn string_table_entry_to_str_slice(e: *mut StringTableEntry) -> &'static str {
    mem::transmute(::std::raw::Slice {
        data: get_ptr_to_str_data(e) as *const u8,
        len: (*e).length as uint
    })
}

//=-------------------------------------------------------------------------------------------------
// TableKey
//=-------------------------------------------------------------------------------------------------
struct TableKey {
    entry_ptr: *mut StringTableEntry
}

impl TableKey {
    fn new(e: *mut StringTableEntry) -> TableKey {
        TableKey {
            entry_ptr: e
        }
    }
}

impl PartialEq for TableKey {
    fn eq(&self, other: &TableKey) -> bool {
        // Allow shallow comparision of the pointers is enough, since the same
        // string is always mapped to the same entry
        (self.entry_ptr as uint) == (other.entry_ptr as uint)
    }
}

impl Eq for TableKey {}

impl ::std::hash::Hash for TableKey {
    fn hash(&self, state: &mut ::std::hash::sip::SipState) {
        unsafe {
            // Only hash based on the string contents of the entry pointed to
            string_table_entry_to_str_slice(self.entry_ptr).hash(state);
        }
    }
}

//=-------------------------------------------------------------------------------------------------
// LookupKey
//=-------------------------------------------------------------------------------------------------
#[deriving(PartialEq, Eq, Hash)]
struct LookupKey<'a> {
    s: &'a str
}

impl<'a> Equiv<TableKey> for LookupKey<'a> {
    fn equiv(&self, other: &TableKey) -> bool {
        unsafe {
            string_table_entry_to_str_slice(other.entry_ptr) == self.s
        }
    }
}

//=-------------------------------------------------------------------------------------------------
// InternedString
//=-------------------------------------------------------------------------------------------------
#[deriving(Eq, PartialEq)]
#[allow(raw_pointer_deriving)]
pub struct InternedString {
    entry_ptr: *mut StringTableEntry
}

impl InternedString {

    // Create a new InternedString instance.
    // Assumes that the pointer to the entry is valid and also has a valid
    // reference count, already taking this new instance into account
    fn create_from_raw_entry_ptr(entry_ptr: *mut StringTableEntry) -> InternedString {
        InternedString { entry_ptr: entry_ptr }
    }

    fn create_with_data_in_place(s: &str) -> InternedString {
        let length = s.as_bytes().len();

        // Make sure we can actually encode this string in place
        debug_assert!(length < mem::size_of::<uint>());

        // The lowest bit is always one for the encoded string
        let mut bits = 1u;

        // Add the length of the string to the left of the tag bit in the lowest
        // byte
        bits |= length << 1;

        let interned_string = unsafe {
            InternedString { entry_ptr: mem::transmute(bits) }
        };
        let ptr_to_string_data = interned_string.get_address_of_encoded_str_data() as *mut u8;

        // copy the string data into the used "pointer" bits
        unsafe {
            ::std::slice::raw::mut_buf_as_slice(ptr_to_string_data, length, |slice| {
                 ::std::slice::bytes::copy_memory(slice, s.as_bytes());
            });
        }

        // Make sure we haven't overwritten anything
        debug_assert!(interned_string.contains_string_in_place());
        debug_assert!((interned_string.entry_ptr as uint >> 1) & 0b1111111 == length);

        interned_string
    }

    fn contains_string_in_place(&self) -> bool {
        (self.entry_ptr as uint) & 1 == 1
    }

    fn get_address_of_encoded_str_data(&self) -> uint {
        debug_assert!(self.contains_string_in_place());

        let address: uint = unsafe {
            mem::transmute(&self.entry_ptr)
        };

        // Adapt for endianess
        if cfg!(target_endian = "big") {
            // x s s s
            address
        } else {
            // s s s x
            address + 1
        }
    }

    fn get_in_place_str_slice<'a>(&'a self) -> &'a str {
        debug_assert!(self.contains_string_in_place());
        // size encoded in lowest byte
        let size = (self.entry_ptr as uint >> 1) & 0b00000111;
        unsafe {
            mem::transmute(::std::raw::Slice {
                data: self.get_address_of_encoded_str_data() as *const u8,
                len: size
            })
        }
    }
}

impl Deref<str> for InternedString {
    fn deref<'a>(&'a self) -> &'a str {
        if self.entry_ptr as uint & 1 == 1 {
            // Data encode in-place in the pointer bytes
            self.get_in_place_str_slice()
        } else {
            unsafe {
                string_table_entry_to_str_slice(self.entry_ptr)
            }
        }
    }
}

impl Drop for InternedString {
    fn drop(&mut self) {
        if self.entry_ptr as uint & 1 == 0 {
            unsafe {
                if (*self.entry_ptr).ref_count.fetch_sub(1, SeqCst) == 1 {
                    let mut table = get_exclusive_table_access(
                        string_table_entry_to_str_slice(self.entry_ptr)
                    );
                    // Might already be gone. See remove() call in get()
                    table.remove(&TableKey::new(self.entry_ptr));
                    deallocate_string_table_entry(self.entry_ptr);
                }
            }
        }
    }
}

impl Clone for InternedString {
    fn clone(&self) -> InternedString {
        if (self.entry_ptr as uint) & 1 == 0 {
            unsafe {
                if (*self.entry_ptr).ref_count.fetch_add(1, SeqCst) == 0 {
                    fail!("strtab: REFERENCE COUNTING LOGIC ERROR")
                }
            }
        }

        InternedString { entry_ptr: self.entry_ptr }
    }
}

impl<S: ::std::hash::Writer> ::std::hash::Hash<S> for InternedString {
    fn hash(&self, hash_state: &mut S) {
        (self.entry_ptr as uint).hash(hash_state);
    }
}

impl ::std::fmt::Show for InternedString {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.deref().fmt(formatter)
    }
}


//=-------------------------------------------------------------------------------------------------
// Table
//=-------------------------------------------------------------------------------------------------

// String table is actually 32 hashtables, each protected by a mutex. Which
// string is stored in which table depends on the first charactor of the string.
// This should reduce contention a bit.

type Table = HashMap<TableKey, *mut StringTableEntry>;

static TABLE_EXPONENT: uint = 5;
static TABLE_COUNT: uint = 1 << TABLE_EXPONENT;
static TABLE_MASK: uint = TABLE_COUNT - 1;

fn get_exclusive_table_access(s: &str) -> MutexGuard<'static, Table> {

    static mut TABLE: [*mut Mutex<Table>, ..TABLE_COUNT] = [0 as *mut Mutex<Table>, ..32];
    static mut INITIALIZE: Once = ONCE_INIT;
    unsafe {
        INITIALIZE.doit(|| {
            for i in range(0, TABLE_COUNT) {
                let mut table: Box<Mutex<Table>> = box Mutex::new(HashMap::new());
                TABLE[i] = (&mut *table) as *mut Mutex<Table>;
                ::std::intrinsics::forget(table);
            }
        });
    }

    debug_assert!(s.len() > 0);

    // Use the first byte to select the table
    let table_index = unsafe {
        (*s.as_bytes().unsafe_get(0) as uint) & TABLE_MASK
    };

    debug_assert!(table_index < TABLE_COUNT);

    unsafe {
        (*TABLE[table_index]).lock()
    }
}


pub fn get(s: &str) -> InternedString {

    if s.len() < mem::size_of::<uint>() {
        // let encoded_ptr = encode_str_in_ptr(s);
        return InternedString::create_with_data_in_place(s);
    }

    let mut table = get_exclusive_table_access(s);

    match table.find_equiv(&LookupKey { s: s }) {
        Some(&existing_entry_ptr) => {
            unsafe {
                if (*existing_entry_ptr).ref_count.fetch_add(1, SeqCst) == 0 {
                    // Oops, there's already a thread waiting to delete this entry.
                    // Allocate a new one, so the deleter is not disturbed...
                    let new_entry_ptr = allocate_string_table_entry_for(s);
                    table.remove(&TableKey::new(existing_entry_ptr));
                    table.insert(TableKey::new(new_entry_ptr), new_entry_ptr);
                    // return InternedString { ptr: new_entry_ptr };
                    InternedString::create_from_raw_entry_ptr(new_entry_ptr)
                } else {
                    InternedString::create_from_raw_entry_ptr(existing_entry_ptr)
                }
            }
        }
        None => {
            let new_entry_ptr = allocate_string_table_entry_for(s);
            table.insert(TableKey::new(new_entry_ptr), new_entry_ptr);
            InternedString::create_from_raw_entry_ptr(new_entry_ptr)
        }
    }
}

// get the ref count of the given string
#[cfg(test)]
fn get_ref_count(s: &str) -> uint {
    if s.len() < mem::size_of::<uint>() {
        return 0;
    }

    let mut table = get_exclusive_table_access(s);

    match table.find_equiv(&LookupKey { s: s }) {
        Some(&entry) => {
            unsafe {
                (*entry).ref_count.load(SeqCst)
            }
        }
        None => 0
    }
}

#[test]
#[cfg(test)]
fn test_key_equiv() {
    let test_string = "test_string";

    let string_table_entry = allocate_string_table_entry_for(test_string);

    assert_eq!(unsafe { string_table_entry_to_str_slice(string_table_entry) },
               test_string);
    let table_key = TableKey::new(string_table_entry);
    let lookup_key = LookupKey { s: test_string };

    assert!(lookup_key.equiv(&table_key));
    assert_eq!(::std::hash::hash(&table_key), ::std::hash::hash(&lookup_key));

    deallocate_string_table_entry(string_table_entry);
}

#[test]
#[cfg(test)]
fn test_storing() {
    let hi1 = get("Hi1!");
    let hi2 = get("Hi2Hi1i1i1i1i1!");
    let hi3 = get("");

    assert_eq!(hi1.deref(), "Hi1!");
    assert_eq!(hi2.deref(), "Hi2Hi1i1i1i1i1!");
    assert_eq!(hi3.deref(), "");
}

#[test]
#[cfg(test)]
fn test_equality() {
    let hi1 = get("Hi!");
    let hi2 = get("Hi!");
    let hi3 = get("Hi!");

    assert_eq!(hi1, hi2);
    assert_eq!(hi2, hi3);
}

#[test]
#[cfg(test)]
fn test_encoding() {
    let small_interned_string = InternedString::create_with_data_in_place("abc");
    assert!(small_interned_string.contains_string_in_place());
    assert_eq!(((small_interned_string.entry_ptr as uint) >> 1) & 0b1111111, 3);
    assert_eq!(small_interned_string.get_in_place_str_slice(), "abc");
}

#[test]
#[cfg(test)]
fn test_ref_count() {
    assert_eq!(get_ref_count("TEEEESSSststts"), 0);
    {
        let _hi1 = get("TEEEESSSststts");
        assert_eq!(get_ref_count("TEEEESSSststts"), 1);
        {
            let _hi2 = get("TEEEESSSststts");
            assert_eq!(get_ref_count("TEEEESSSststts"), 2);

            {
                let _hi3 = get("TEEEESSSststts");
                assert_eq!(get_ref_count("TEEEESSSststts"), 3);
            }
            assert_eq!(get_ref_count("TEEEESSSststts"), 2);
        }
        assert_eq!(get_ref_count("TEEEESSSststts"), 1);
    }
    assert_eq!(get_ref_count("TEEEESSSststts"), 0);
}

#[test]
#[cfg(test)]
fn stress_test() {
    use std::rand;
    use std::sync::Future;

    let mut futures: Vec<Future<()>> = vec!();

    for _ in range(0u, 20) {
        let future = Future::spawn(proc() {
            for _ in range(0u, 10000u) {
                let case: uint = (rand::random::<f32>() * 4f32) as uint;

                match case {
                    0 => {
                        get("acvaafsafasdasdasda");
                    }
                    1 => {
                        let x = get("acvaafsafasdasdasda");
                        {
                            let _y = x.clone();
                            {
                                let _z = x.clone();
                            }
                        }
                    }
                    _ => {
                        let string = get_random_str();
                        let r = get(string.as_slice());
                        {
                            let _x = r.clone();
                        }
                    }
                }
            }
        });

        futures.push(future);
    }

    for future in futures.into_iter() {
        future.unwrap();
    }

    fn get_random_str() -> String {
        let length = (rand::random::<f32>() * 20f32) as uint;

        let mut s = String::with_capacity(length);

        for _ in range(0, length) {
            s.push(rand::random::<char>());
        }

        return s;
    }
}