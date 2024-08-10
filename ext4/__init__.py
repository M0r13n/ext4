#!/usr/bin/env python3
import abc
import datetime
import enum
import struct
import dataclasses
import typing

# --- Constants ---

EXT4MAGIC = 0xEF53

# --- Helpers ---

LE16 = '<H'
LE32 = '<L'
U8 = 'B'


def read_little_endian(raw: bytes, offset: int, fmt: str) -> int:
    return struct.unpack_from(fmt, raw, offset)[0]


T = typing.TypeVar('T', bound='Ext4Struct')


class Ext4Struct:

    FIELDS: list[tuple[str, int, str]]
    HUMAN_NAME: str

    @classmethod
    def from_bytes(cls: typing.Type[T], block: bytes) -> T:
        kwargs = {}
        for attr, offset, size in cls.FIELDS:
            kwargs[attr] = read_little_endian(block, offset, size)
        return cls(**kwargs)

    def pretty_print(self):
        print(f'struct {self.HUMAN_NAME}:')
        for f in dataclasses.fields(self):
            print(f"  {f.name}: {getattr(self, f.name)}")

# --- Superblock ---


EXT4SUPERBLOCK_FIELDS = [
    # attribute, offset, size
    ('s_inodes_count', 0x0, LE32),
    ('s_blocks_count_lo', 0x4, LE32),
    ('s_free_blocks_count_lo', 0xC, LE32),
    ('s_free_inodes_count', 0x10, LE32),
    ('s_first_data_block', 0x14, LE32),
    ('s_log_block_size', 0x18, LE32),
    ('s_blocks_per_group', 0x20, LE32),
    ('s_inodes_per_group', 0x28, LE32),
    ('s_mtime', 0x2C, LE32),
    ('s_wtime', 0x30, LE32),
    ('s_magic', 0x38, LE16),
    ('s_first_ino', 0x54, LE32),
    ('s_inode_size', 0x58, LE32),
    ('s_desc_size', 0xFE, LE16),
]


@dataclasses.dataclass
class Ext4Superblock(Ext4Struct):

    FIELDS = EXT4SUPERBLOCK_FIELDS
    HUMAN_NAME = 'ext4_super_block'

    # NOTE: not all fields implemented
    s_inodes_count: int
    s_blocks_count_lo: int
    s_free_blocks_count_lo: int
    s_free_inodes_count: int
    s_first_data_block: int
    s_log_block_size: int
    s_blocks_per_group: int
    s_inodes_per_group: int
    s_mtime: int
    s_wtime: int
    s_magic: int
    s_first_ino: int
    s_inode_size: int
    s_desc_size: int

    def __post_init__(self):
        if self.s_magic != EXT4MAGIC:
            raise ValueError(f'no ext4 superblock: invalid magic number {self.s_magic}')

    def get_block_size(self) -> int:
        return 2 ** (10 + self.s_log_block_size)


EXT4GROUP_DESCRIPTOR_FIELDS = [
    # attribute, offset, size
    ('bg_block_bitmap_lo', 0x0, LE32),
    ('bg_inode_bitmap_lo', 0x4, LE32),
    ('bg_inode_table_lo', 0x8, LE32),
    ('bg_block_bitmap_hi', 0x20, LE32),
    ('bg_inode_bitmap_hi', 0x24, LE32),
    ('bg_inode_table_hi', 0x28, LE32),
]


@dataclasses.dataclass
class Ext4GroupDescriptor(Ext4Struct):

    FIELDS = EXT4GROUP_DESCRIPTOR_FIELDS
    HUMAN_NAME = 'ext4_group_desc'

    bg_block_bitmap_lo: int
    bg_inode_bitmap_lo: int
    bg_inode_table_lo: int
    bg_block_bitmap_hi: int
    bg_inode_bitmap_hi: int
    bg_inode_table_hi: int


@dataclasses.dataclass
class Ext4XattrHeader(Ext4Struct):
    FIELDS = [
        ('h_magic', 0x0, LE32),
        ('h_refcount', 0x4, LE32),
        ('h_blocks', 0x8, LE32),
        ('h_hash', 0xC, LE32),
        ('h_checksum', 0x10, LE32),
        ('h_reserved', 0x14, LE32),
    ]
    HUMAN_NAME = 'ext4_xattr_header'

    h_magic: int
    h_refcount: int
    h_blocks: int
    h_hash: int
    h_checksum: int
    h_reserved: int


@dataclasses.dataclass
class Ext4XattrEntry(Ext4Struct):
    FIELDS = [
        ('e_name_len', 0x0, U8),
        ('e_name_index', 0x1, U8),
        ('e_value_offs', 0x2, LE16),
        ('e_value_inum', 0x4, LE32),
        ('e_value_size', 0x8, LE32),
        ('e_hash', 0xC, LE32),
    ]
    HUMAN_NAME = 'ext4_xattr_entry'

    e_name_len: int
    e_name_index: int
    e_value_offs: int
    e_value_inum: int
    e_value_size: int
    e_hash: int
    e_name: bytes = dataclasses.field(default=b'NA')
    value: bytes = dataclasses.field(default=b'NA')

    @property
    def name(self) -> str:
        return EXT4_XATTR_PREFIXES[self.e_name_index] + self.e_name.decode()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name}={self.value})"

    def __bool__(self) -> bool:
        return bool(self.e_name_len | self.e_name_index | self.e_value_offs | self.e_value_inum)


EXT4_XATTR_PREFIXES = {
    0: "",
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    6: "security.",
    7: "system.",
    8: "system.richacl"
}

EXT4INODE_FIELDS = [
    # attribute, offset, size
    ('i_mode', 0x0, LE16),
    ('i_uid', 0x2, LE16),
    ('i_size_lo', 0x4, LE32),
    ('i_atime', 0x8, LE32),
    ('i_ctime', 0xC, LE32),
    ('i_mtime', 0x10, LE32),
    ('i_gid', 0x18, LE16),
    ('i_blocks_lo', 0x1C, LE32),
    ('i_flags', 0x20, LE32),
    ('i_block', 0x28, '60s'),  # 60 bytes
    ('i_file_acl_lo', 0x68, LE32),
    ('i_size_high', 0x6C, LE32),
    ('i_extra_isize', 0x80, LE16),
]


class InodeFileType(enum.IntEnum):
    S_IFIFO = 0x1000  # FIFO
    S_IFCHR = 0x2000  # Character device
    S_IFDIR = 0x4000  # Directory
    S_IFBLK = 0x6000  # Block device
    S_IFREG = 0x8000  # Regular file
    S_IFLNK = 0xA000  # Symbolic link
    S_IFSOCK = 0xC000  # Socket

    @classmethod
    def from_raw(cls, i_mode: int) -> 'InodeFileType':
        if i_mode & cls.S_IFIFO != 0:
            return InodeFileType.S_IFIFO
        elif i_mode & cls.S_IFCHR != 0:
            return InodeFileType.S_IFCHR
        elif i_mode & cls.S_IFDIR != 0:
            return InodeFileType.S_IFDIR
        elif i_mode & cls.S_IFBLK != 0:
            return InodeFileType.S_IFBLK
        elif i_mode & cls.S_IFREG != 0:
            return InodeFileType.S_IFREG
        elif i_mode & cls.S_IFLNK != 0:
            return InodeFileType.S_IFLNK
        elif i_mode & cls.S_IFSOCK != 0:
            return InodeFileType.S_IFSOCK
        raise ValueError(f'unknown inode file type: {i_mode}')


@dataclasses.dataclass
class Ext4Inode(Ext4Struct):
    FIELDS = EXT4INODE_FIELDS
    HUMAN_NAME = 'ext4_inode'

    i_mode: int
    i_uid: int
    i_size_lo: int
    i_atime: int
    i_ctime: int
    i_mtime: int
    i_gid: int
    i_blocks_lo: int
    i_flags: int
    i_block: bytes
    i_file_acl_lo: int
    i_size_high: int
    i_extra_isize: int


class Ext4Permission(enum.IntEnum):
    S_IXOTH = 0x1
    S_IWOTH = 0x2
    S_IROTH = 0x4

    S_IXGRP = 0x8
    S_IWGRP = 0x10
    S_IRGRP = 0x20

    S_IXUSR = 0x40
    S_IWUSR = 0x80
    S_IRUSR = 0x100


class Inode:

    def __init__(self, i_num: int, offset: int, e4inode: Ext4Inode, filesystem: 'Ext4Filesystem') -> None:
        self.i_num = i_num
        self.offset = offset
        self.e4inode = e4inode
        self.file_type = InodeFileType.from_raw(e4inode.i_mode)
        self.filesystem = filesystem

    def __repr__(self):
        return f'Inode(i_num={self.i_num}, offset={self.offset})'

    @property
    def is_file(self):
        return self.file_type == InodeFileType.S_IFREG

    @property
    def is_dir(self):
        return self.file_type == InodeFileType.S_IFDIR

    @property
    def size(self):
        return self.e4inode.i_size_high << 32 | self.e4inode.i_size_lo

    def read(self):
        bs = ByteStream.create(self)
        return bs.read()

    def iter(self) -> typing.Generator['Ext4DirEntry2', None, None]:
        if not self.is_dir:
            raise TypeError('can only iterate directories')

        # a directory is more or less a flat file that maps an arbitrary byte string (usually ASCII) to an inode number on the filesystem
        # EXT4_INDEX_FL: has hashed indexes. linear otherwise.
        if self.e4inode.i_flags & 0x1000 != 0:
            raise NotImplementedError('hashed directories not supported yet')

        bs = ByteStream.create(self)

        # NOTE: directory entries are not split across filesystem blocks!
        for block in bs.read_blocks():
            while block:
                de = Ext4DirEntry2.from_bytes(block)
                if de.inode != 0:
                    yield de
                block = block[de.rec_len:]
                if de.inode == 0:
                    break


class Ext4Filesystem:

    def __init__(self, path: str) -> None:
        # open raw image
        self.path = path
        self.fd = open(self.path, 'rb')

        # boot block is empty (1024 bytes)
        self.sb = Ext4Superblock.from_bytes(self.read_bytes(1024, 4096))

        # load the group descriptor table
        self.gdt: list[Ext4GroupDescriptor] = []
        self.read_gdt()

    def close(self):
        self.fd.close()
        del self.fd

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fd.close()

    def read_bytes(self, offset, length):
        self.fd.seek(offset)
        b = self.fd.read(length)
        return b

    def read_blocks(self, i, n):
        return self.read_bytes(i * self.sb.get_block_size(), n * self.sb.get_block_size())

    def read_gdt(self):
        num_groups = self.sb.s_inodes_count // self.sb.s_inodes_per_group
        # the group descriptor table is found in the block following the super block
        group_desc_table_offset = self.sb.get_block_size()
        for idx in range(num_groups):
            group_desc_offset = group_desc_table_offset + idx * self.sb.s_desc_size
            # the group descriptor has has a size of 64 bytes (on 64bit at least)
            self.gdt.append(Ext4GroupDescriptor.from_bytes(self.read_bytes(group_desc_offset, 64)))

    def get_root(self) -> Inode:
        # root inode is always the number 2
        return self.get_inode(2)

    def get_inode(self, idx: int) -> Inode:
        # the group of the inode
        group_idx, inode_table_entry_idx = self.get_inode_group(idx)
        # location of inode table
        inode_table_offset = self.gdt[group_idx].bg_inode_table_lo * self.sb.get_block_size()
        # location of inode in the inode table
        inode_offset = inode_table_offset + inode_table_entry_idx * self.sb.s_inode_size
        e4inode = Ext4Inode.from_bytes(self.read_bytes(inode_offset, 160))
        return Inode(idx, inode_offset, e4inode, self)

    def get_inode_group(self, idx: int):
        # return (group_idx, inode_table_entry_idx)
        group_idx = (idx - 1) // self.sb.s_inodes_per_group
        inode_table_entry_idx = (idx - 1) % self.sb.s_inodes_per_group
        return (group_idx, inode_table_entry_idx)

    def iter_dir(self, inode: Inode):
        if not inode.is_dir:
            raise ValueError('can only iterate over directories')
        if inode.e4inode.i_flags & 0x1000 != 0:
            raise NotImplementedError('directory has hashed indexes (EXT4_INDEX_FL)')
        return None

    def get_xattrs(self, inode: Inode) -> typing.Generator[Ext4XattrEntry, None, None]:
        # two places
        # end of each inode entry and the beginning of the next inode entry
        # inode.i_extra_isize = 28 and sb.inode_size = 256, then there are 256 - (128 + 28) = 100 bytes for this
        # second: y inode.i_file_acl
        avail = self.sb.s_inode_size - (128 + inode.e4inode.i_extra_isize)
        data = self.read_bytes(inode.offset + 128 + inode.e4inode.i_extra_isize, avail)
        assert data[0:4] == b"\x00\x00\x02\xea"  # magic number: 0xEA020000 (ext4_xattr_ibody_header)

        i = 4
        while i < len(data):
            xattr = Ext4XattrEntry.from_bytes(data[i:])
            xattr.e_name = data[0x10 + i: 0x10 + i + xattr.e_name_len]

            if not xattr:
                # end of xattr list
                return

            # extract name (null terminated)
            j = -1
            for j, b in enumerate(data[0x4 + xattr.e_value_offs:]):
                if b == 0:
                    break

            if j == -1:
                raise ValueError('xattr not null terminated')

            xattr.value = data[0x4 + xattr.e_value_offs:0x4 + xattr.e_value_offs + j]

            yield xattr

            i += (16 + xattr.e_name_len + 1)  # size of Ext4XattrEntry (last byte is null termination)


@dataclasses.dataclass
class Ext4ExtentHeader(Ext4Struct):
    FIELDS = [
        ('eh_magic', 0x0, LE16),
        ('eh_entries', 0x2, LE16),
        ('eh_max', 0x4, LE16),
        ('eh_depth', 0x6, LE16),
        ('eh_generation', 0x8, LE32),
    ]
    HUMAN_NAME = 'ext4_extent_header'

    eh_magic: int
    eh_entries: int
    eh_max: int
    eh_depth: int
    eh_generation: int


@dataclasses.dataclass
class Ext4Extent(Ext4Struct):
    FIELDS = [
        ('ee_block', 0x0, LE32),
        ('ee_len', 0x4, LE16),
        ('ee_start_hi', 0x6, LE16),
        ('ee_start_lo', 0x8, LE32),
    ]
    HUMAN_NAME = 'ext4_extent'

    ee_block: int
    ee_len: int
    ee_start_hi: int
    ee_start_lo: int


@dataclasses.dataclass
class Ext4ExtentIdx(Ext4Struct):
    FIELDS = [
        ("ee_block", 0x0, LE32),
        ("ei_leaf_lo", 0x4, LE32),
        ("ei_leaf_hi", 0x8, LE16),
        ("ei_unused", 0x0, LE16)
    ]
    HUMAN_NAME = 'ext4_extent_idx'

    ee_block: int
    ei_leaf_lo: int
    ei_leaf_hi: int
    ei_unused: int


@dataclasses.dataclass
class Ext4DirEntry2(Ext4Struct):
    FIELDS = [
        ('inode', 0x0, LE32),
        ('rec_len', 0x4, LE16),
        ('name_len', 0x6, U8),
        ('file_type', 0x7, U8),
    ]
    HUMAN_NAME = 'ext4_dir_entry_2'

    inode: int
    rec_len: int
    name_len: int
    file_type: int
    name: str = dataclasses.field(init=False)

    @classmethod
    def from_bytes(cls: typing.Type[T], data: bytes) -> T:
        de = super().from_bytes(data[:8])
        de.name = data[8: 8 + de.name_len]
        return de

# Files


class Ext4InodeFlags:
    EXT4_EXTENTS_FL = 0x80000
    EXT4_INLINE_DATA_FL = 0x10000000


class ByteStream(abc.ABC):

    def __init__(self, inode: Inode) -> None:
        self.inode = inode

    @staticmethod
    def create(inode: Inode) -> 'ByteStream':
        if inode.e4inode.i_flags & Ext4InodeFlags.EXT4_EXTENTS_FL != 0:
            return ExtentByteStream(inode)
        elif inode.e4inode.i_flags & Ext4InodeFlags.EXT4_INLINE_DATA_FL != 0:
            return InlineByteStream(inode)
        else:
            raise ValueError('can only read extents or inline data')

    @abc.abstractmethod
    def iter_blocks(self):
        pass

    def read_blocks(self, blocks: int = -1):
        """Read consecutive blocks as bytes"""
        end = self.inode.size
        block_size = self.inode.filesystem.sb.get_block_size()
        bytes_read = 0

        for i, block_no in enumerate(self.iter_blocks()):
            if blocks != -1 and i >= blocks:
                return
            block_data = self.inode.filesystem.read_blocks(block_no, 1)
            bytes_to_yield = min(block_size, end - bytes_read)

            if bytes_read + bytes_to_yield > end:
                bytes_to_yield = end - bytes_read

            yield block_data[:bytes_to_yield]
            bytes_read += bytes_to_yield

            if bytes_read >= end:
                return

    def read(self):
        return b"".join(self.read_blocks(-1))


class ExtentByteStream(ByteStream):

    def iter_blocks(self):
        """Yield consecutive number of blocks for this extent.
        e.g.: [15, 16, 17, ...]"""

        def traverse_extent_tree(block_data, depth):
            header = Ext4ExtentHeader.from_bytes(block_data[:12])
            assert header.eh_magic == 0xF30A

            if depth == 0:
                # is leaf
                for i in range(1, header.eh_entries + 1):
                    extent = Ext4Extent.from_bytes(block_data[i * 12:(i + 1) * 12])
                    assert extent.ee_len <= 32768, "extent uninitialized"
                    for block_no in range(extent.ee_len):
                        yield extent.ee_start_lo + block_no
            else:
                # is internal node
                for i in range(1, header.eh_entries + 1):
                    idx = Ext4ExtentIdx.from_bytes(block_data[i * 12:(i + 1) * 12])
                    block_idx = idx.ei_leaf_lo * self.inode.filesystem.sb.get_block_size()
                    next_block_data = self.inode.filesystem.read_bytes(block_idx, self.inode.filesystem.sb.get_block_size())
                    yield from traverse_extent_tree(next_block_data, depth - 1)

        # Start the traversal from the root
        initial_block_data = self.inode.e4inode.i_block
        header = Ext4ExtentHeader.from_bytes(initial_block_data[:12])
        assert header.eh_magic == 0xF30A

        yield from traverse_extent_tree(initial_block_data, header.eh_depth)


class InlineByteStream(ByteStream):
    pass


def human_mode(mode):
    mode_string = ''
    fields = (
        Ext4Permission.S_IRUSR,
        Ext4Permission.S_IWUSR,
        Ext4Permission.S_IXUSR,
        Ext4Permission.S_IRGRP,
        Ext4Permission.S_IWGRP,
        Ext4Permission.S_IXGRP,
        Ext4Permission.S_IROTH,
        Ext4Permission.S_IWOTH,
        Ext4Permission.S_IXOTH,
    )
    for mask, char in zip(fields, 'rwxrwxrwx'):
        if mode & mask != 0:
            mode_string += char
        else:
            mode_string += '-'
    return mode_string


def ls(root: Inode):
    for entry in root.iter():
        # .rwxrwxrwx root root 12301 Jul 13 11:01 test.file
        inode = root.filesystem.get_inode(entry.inode)
        prefix = 'd' if inode.is_dir else '.'
        mode = human_mode(inode.e4inode.i_mode)
        size = inode.e4inode.i_size_high << 32 | inode.e4inode.i_size_lo
        mtime = datetime.datetime.fromtimestamp(inode.e4inode.i_mtime)

        print(f'{prefix}{mode} {inode.e4inode.i_uid} {inode.e4inode.i_gid} {size} {mtime.isoformat()} {entry.name.decode()}')


def cat(root: Inode):
    if not root.is_file:
        raise TypeError('can only cat files')
    print(root.read().decode(), end='')
