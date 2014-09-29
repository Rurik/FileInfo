FileInfo
========

This is a very basic file metadata gathering script, intended primarily for executables and DLLs. It was designed to make standardized output from multiple executable for indexing and referencing. It uses pefile (https://code.google.com/p/pefile/) to extract metadata from the executable, plus outputs the results of 'file' (from python-magic or file.exe) and 'signsrch'. It also uses ssdeep (pydeep) (http://ssdeep.sourceforge.net/) to perform fuzzy hashing.

```
File Name       : fuzzy.dll
File Size       : 33,280 bytes
MD5             : 859d701604404684175a9b096a2b9bd2
SHA1            : 82563c790d6d2bd32195b5f7db7338d37bbda89a
Fuzzy           : 768:BqzAbafd6zPosAwNuE0ihe7C5pseW1mpNaps:BUQ/PL/he7C5p0cNaq
Magic           : PE32 executable for MS Windows (DLL) (console) Intel 80386 32-bit
Import Hash     : 776cfbf8013e6bcedf2728d7ee097c91
Compiled Time   : Wed Jul 17 07:01:44 2013 UTC
PE Sections (7) : Name       Size       MD5
                  .text      27,136     eb567ca808c974bcd04a1ad17ca4a27e
                  .data      512        e4b56b092ba021dd811e5cae7bb16288
                  .rdata     1,536      93e3129dff18dc5139a4ee6bdf35c533
                  .bss       0          d41d8cd98f00b204e9800998ecf8427e
                  .edata     512        ef0ebfa26beeaf87a286aef240151003
                  .idata     1,536      9797a026f32c7025fc54d387490044bd
                  .reloc     1,024      7e60825e9290b4da95a8a5e7112bf66b
Original DLL    : fuzzy.dll
DLL Exports (12): Ordinal  Name
                  1        _get_output_format
                  2        edit_distn
                  3        find_file_size
                  4        fuzzy_compare
                  5        fuzzy_digest
                  6        fuzzy_free
                  7        fuzzy_hash_buf
                  8        fuzzy_hash_file
                  9        fuzzy_hash_filename
                  10       fuzzy_hash_stream
                  11       fuzzy_new
                  12       fuzzy_update
SignSrch        : offset   num  description [bits.endian.size]
                  65a49000 1996 rfc3548 Base 64 Encoding with URL and Filename Safe Alphabet [..62]
                  65a49000 2005 B64EncodeTable [..64]
                  

                  
File Name       : Challenge1.exe
File Size       : 120,832
CRC32           : d9573080
MD5             : 66692c39aab3f8e7979b43f2a31c104f
SHA1            : 5f7d1552383dc9de18758aa29c6b7e21ca172634
SHA256          : c1b55c829a8420fa41e7a31344b6427045cea288458fe1c0f32cae47b2e812f2
Fuzzy           : 3072:vaL7nzo5UC2ShGACS3XzXl/ZPYHLy7argeZX:uUUC2SHjpurG
Magic           : PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
.NET Version    : v2.0.50727
Compiled Time   : Wed Jul  2 19:01:33 2014 UTC
PE Sections (3) : Name       Size       MD5
                  .text      118,272    e4c64d5b55603ecef3562099317cad76
                  .rsrc      1,536      6adbd3818087d9be58766dccc3f5f2bd
                  .reloc     512        34db3eafce34815286f13c2ea0e2da70
```
