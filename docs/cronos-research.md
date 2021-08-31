# About Cronos databases.

A _cronos database_ consists of those files

    CroBank.dat
    CroBank.tad
    CroIndex.dat
    CroIndex.tad
    CroStru.dat
    CroStru.tad

and a Vocabulary database with another set of these files in a sub directory Voc/

`CroIndex.*` can be ignored, unless we suspect there to be residues of old data. All words are serialized in little endianess.

Additionally there are the `CroSys.dat` and `CroSys.tad` files in the cronos application directory, which list the currently
known databases.

## app installation

On a default Windows installation, the CronosPro app shows with several encoding issues that can be fixed like this: 

    reg set HKLM\System\CurrentControlSet\Control\Nls\Codepage 1250=c_1251.nls 1252=c_1251.nls

[from](https://ixnfo.com/en/question-marks-instead-of-russian-letters-a-solution-to-the-problem-with-windows-encoding.html)

Also note that the v3 cronos app will run without problem on a linux machine using [wine](https://winehq.org/)

##Files ending in .dat

All .dat files start with a 19 byte header:

    char      magic[8]      // allways: 'CroFile\x00'
    uint16    unknown
    char      version[5]    // 01.02, 01.03, 01.04
    uint16    encoding      // bitfield: bit0 = KOD, bit1 = ?
    uint16    blocksize     // 0x0040, 0x0200 or 0x0400

Most Bank files use blocksize == 0x0040
most Index files use blocksize == 0x0400
most Stru files use blocksize == 0x0200

This is followed by a block of 0x101 or 0x100 minus 19 bytes seemingly random data.

The unknown word is unclear but seems not to be random, might be a checksum.

##Files ending in .tad

The first two `uint32` are the number of deleted records and the tad offset to the first deleted entry.
The deleted entries form a linked list, with the size always 0xFFFFFFFF.

Depending on the version in the `.dat` header, `.tad` use either 32 bit or 64 bit file offsets

version `01.02` and `01.04` use 32 bit offsets:

    uint32 offset
    uint32 size       // with flag in upper bit, 0 -> large record
    uint32 checksum   // but sometimes just 0x00000000, 0x00000001 or 0x00000002

version `01.03` uses 64 bit offsets:

    uint64 offset
    uint32 size       // with flag in upper bit, 0 -> large record
    uint32 checksum   // but sometimes just 0x00000000, 0x00000001 or 0x00000002

where size can be 0xffffffff (indicating a free/deleted block).
Bit 31 of the size indicates that this is an extended record.

Extended records start with plaintext: { uint32 offset, uint32 size }  or { uint64 offset, uint32 size }


## the 'old format'

The original description made it look like there were different formats for the block references.

This was found in previously existing documentation, but no sample databases with this format were found so far.

If the .dat file has a version of 01.03 or later, the corresponding .tad file looks like this:

    uint32_t offset
    uint32_t size       // with flag in upper bit, 0 -> large record
    uint32_t checksum   // but sometimes just 0x00000000, 0x00000001 or 0x00000002
    uint32_t unknownn   // mostly 0

The old description would also assume 12 byte reference blocks but a packed struct, probably if the CroFile version is 01.01.

    uint32 offset1
    uint16 size1
    uint32 offset2
    uint16 size2

with the first chunk read from offset1 with length size1 and potentially more parts with total length of size2 starting at file offset offset2 with the first `uint32` of the 256 byte chunk being the next chunk's offset and a maximum of 252 bytes being actual data.

However, I never found files with .tad like that. Also the original description insisted on those chunks needing the decode-magic outlined below, but the python implementation only does that for CroStru files and still seems to produce results.

##CroStru

Interesting files are CroStru.dat containing metadata on the database within blocks whose size and length are found in CroStru.tad. These blocks are rotated byte wise using an sbox found in the cro2sql sources and then each byte is incremented by a one byte counter which is initialised by a per block offset. The sbox looks like this:

    unsigned char kod[256] = {
      0x08, 0x63, 0x81, 0x38, 0xa3, 0x6b, 0x82, 0xa6,
      0x18, 0x0d, 0xac, 0xd5, 0xfe, 0xbe, 0x15, 0xf6,
      0xa5, 0x36, 0x76, 0xe2, 0x2d, 0x41, 0xb5, 0x12,
      0x4b, 0xd8, 0x3c, 0x56, 0x34, 0x46, 0x4f, 0xa4,
      0xd0, 0x01, 0x8b, 0x60, 0x0f, 0x70, 0x57, 0x3e,
      0x06, 0x67, 0x02, 0x7a, 0xf8, 0x8c, 0x80, 0xe8,
      0xc3, 0xfd, 0x0a, 0x3a, 0xa7, 0x73, 0xb0, 0x4d,
      0x99, 0xa2, 0xf1, 0xfb, 0x5a, 0xc7, 0xc2, 0x17,
      0x96, 0x71, 0xba, 0x2a, 0xa9, 0x9a, 0xf3, 0x87,
      0xea, 0x8e, 0x09, 0x9e, 0xb9, 0x47, 0xd4, 0x97,
      0xe4, 0xb3, 0xbc, 0x58, 0x53, 0x5f, 0x2e, 0x21,
      0xd1, 0x1a, 0xee, 0x2c, 0x64, 0x95, 0xf2, 0xb8,
      0xc6, 0x33, 0x8d, 0x2b, 0x1f, 0xf7, 0x25, 0xad,
      0xff, 0x7f, 0x39, 0xa8, 0xbf, 0x6a, 0x91, 0x79,
      0xed, 0x20, 0x7b, 0xa1, 0xbb, 0x45, 0x69, 0xcd,
      0xdc, 0xe7, 0x31, 0xaa, 0xf0, 0x65, 0xd7, 0xa0,
      0x32, 0x93, 0xb1, 0x24, 0xd6, 0x5b, 0x9f, 0x27,
      0x42, 0x85, 0x07, 0x44, 0x3f, 0xb4, 0x11, 0x68,
      0x5e, 0x49, 0x29, 0x13, 0x94, 0xe6, 0x1b, 0xe1,
      0x7d, 0xc8, 0x2f, 0xfa, 0x78, 0x1d, 0xe3, 0xde,
      0x50, 0x4e, 0x89, 0xb6, 0x30, 0x48, 0x0c, 0x10,
      0x05, 0x43, 0xce, 0xd3, 0x61, 0x51, 0x83, 0xda,
      0x77, 0x6f, 0x92, 0x9d, 0x74, 0x7c, 0x04, 0x88,
      0x86, 0x55, 0xca, 0xf4, 0xc1, 0x62, 0x0e, 0x28,
      0xb7, 0x0b, 0xc0, 0xf5, 0xcf, 0x35, 0xc5, 0x4c,
      0x16, 0xe0, 0x98, 0x00, 0x9b, 0xd9, 0xae, 0x03,
      0xaf, 0xec, 0xc9, 0xdb, 0x6d, 0x3b, 0x26, 0x75,
      0x3d, 0xbd, 0xb2, 0x4a, 0x5d, 0x6c, 0x72, 0x40,
      0x7e, 0xab, 0x59, 0x52, 0x54, 0x9c, 0xd2, 0xe9,
      0xef, 0xdd, 0x37, 0x1e, 0x8f, 0xcb, 0x8a, 0x90,
      0xfc, 0x84, 0xe5, 0xf9, 0x14, 0x19, 0xdf, 0x6e,
      0x23, 0xc4, 0x66, 0xeb, 0xcc, 0x22, 0x1c, 0x5c,
    };


given the `shift`, the encoded data: `a[0]..a[n-1]` and the decoded data: `b[0]..b[n-1]`, the encoding works as follows:

    decode: b[i] = KOD[a[i]] - (i+shift)
    encode: a[i] = INV[b[i] + (i+shift)]


The original description of an older database format called the per block counter start offset 'sistN' which seems to imply it to be constant for certain entries. They correspond to a "system number" of meta entries visible in the database software. For encoded records this is their primary key.

In noticed that the first 256 bytes of CroStru.dat look close to identical (except the first 16 bytes) than CroBank.dat.

The toplevel table-id for CroStru and CroSys is #3, while referenced records have tableid #4.

##CroBank

CroBank.dat contains the actual database entries for multiple tables as described in the CroStru file. After each chunk is re-assembled (and potentially decoded with the per block offset being the record number in the .tad file).

Its first byte defines, which table it belongs to. It is encoded in cp1251 (or possibly IBM866) with actual column data separated by 0x1e.

There is an extra concept of sub fields in those columns, indicated by a 0x1d byte.

Fields of field types 6 and 9 start with an 0x1b byte, followed by a uint32 size of the actual fields. It may then contain further 0x1e bytes which indicate sub field separators.

If used for field type 6, the field begins with two uint32 (the first one mostly 0x00000001, the second one the size of the next strings) followed by three 0x1e separated strings containing file name, file extension and system number of the actual file record data referred to by this record.

## structure definitions

records start numbering at '1'.
Names are stored as: `byte strlen + char value[strlen]`

The first entry contains:

    uint8
    array {
        Name keyname
        uint32 index_or_size;   // size when bit31 is set.
        uint8 data[size]
    }

this results in a dictionary, with keys like: `Bank`, `BankId`, `BankTable`, `Base`nnn, etc.

the `Base000` entry contains the record number for the table definition of the first table.

## table definitions

    uint16 unk1
    union {
        uint8 shortversion; // 1
        uint16 version;     // >1
    }
    uint8 somelen;     // 5 or 9
    struct {
        uint8 unk3
        uint32 unk4    // not there when 'somelen'==5
        uint32 unk5
    }
    uint32 tableid
    Name   tablename
    Name   abbreviation
    uint32 unk7
    uint32 nrfields

    array {
      uint16 entrysize    -- total nr of bytes in this entry.
      uint16 fieldtype    // see below
      uint32 fieldindex1  // presentation index (i.e. where in the UI it shows)
      Name   fieldname
      uint32 flags
      uint8  alwaysone    // maybe the 'minvalue'
      uint32 fieldindex2  // serialization index (i.e. where in the record in the .dat it appears)
      uint32 fieldsize    // max fieldsize
      uint32 unk4
      ...
      followed by remaining unknown bytes
    } fields[nrfields]

    uint32 extradatstr    // amount of unknown length indexed data strings between field definition blocks
    array {
      uint16 datalen
      uint8[datalen]
    } datastrings[extradatstr]

    uint32 unk8
    uint8  fielddefblock  // always 2, probably the number of this block of field definitions
    uint32 unk9

    uint32 nrextrafields
    array {
      ... as above
    } extrafields[nrextrafields]

    followed by remaining unknown bytes
    ...


    In order to have field definitions for all the fields in a record from the .dat for that table,
    fields.append(extrafields) must be sorted by their fieldindex2.

## field types

The interface gives a list of field types I can select for table columns:

* 0  - Системный номер = Primary Key ID
* 1  - Числовое = Numeric
* 2  - Текстовое = Text
* 3  - Словарное = Dictionary
* 4  - Дата = Date
* 5  - Время = Time
* 6  - Фаил = File (internal)
* 29 - Внеэшний фаил = File (external)
* 7  - Прямая ссылка = Direkt link
* 8  - Обратная ссылка = Back link
* 9  - Прямаяь-Обратная ссылка = Direct-Reverse link
* 17 - Связь по полю = Field communication

Other unassigned values in the table entry definition are

* Dictionary Base (defaults to 0)
* номер в записи = number in the record
* Длина Поля = Field size
* Flags:
  * (0x2000) Множественное = Multiple
  * (0x0800) Информативное = Informative
  * (0x0040) Некорректируемое = Uncorrectable
  * (0x1000) поиск на вводе = input search
  * (?) симбольное =  symbolic
  * (?) Лемматизировать = Lemmatize
  * (?) поиск по значениям = search by values
  * (0x0200) замена непустого значения = replacement of a non-empty value
  * (0x0100) замена значения = value replacement
  * (0x0004) автозаполнения = autocomplete
  * (?) корневая связь = root connection
  * (?) допускать дубли = allow doubles
  * (0x0002) обязательное = obligatory

## compressed records

some records are compressed, the format is like this:

    multiple-chunks {
        uint16 size;     // stored in bigendian format.
        uint8   head[2] = { 8, 0 }
        uint32 crc32
        uint8   compdata[size-6]
    }
    uint8   tail[3] = { 0, 0, 2 }


# v4 format

The header version 01.11 indicates a database created with cronos v4.x.

## .tad

A 4 dword header:

    dword -2
    dword nr deleted
    dword first deleted
    dword 0

16 byte records:
    qword offset,  with flags in upper 8 bits.
    dword size
    dword unk

flags:
    02,03  - deleted record.
    04  - compressed { int16be size; int16be flag int32le crc; byte data[size-6]; } 00 00 02
    00  - extended record

## .dat

The .dat file of a 01.11 database has 64bit offsets, like the 01.03 file format.

