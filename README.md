strtab
======

Rust module for interning strings.

Features
--------

- Interning is thread-safe.
- Memory-managed: String data is freed after last reference goes out of scope.
- Uses pointer-tagging to store small strings (less than 8 character in a 64 bit process) directly in the pointer field, which means that neither allocation nor synchronization is needed in this case.
- Comparing interned strings is just a pointer comparison.
- No documentation whatsoever.