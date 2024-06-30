# https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html#super-block
#!/usr/bin/env python3
import struct
import dataclasses

# --- Constants ---

EXT4MAGIC = 0xEF53

# --- Helpers ---

LE16 = '<H'
LE32 = '<L'
U8 = 'B'


def read_little_endian(raw: bytes, offset: int, fmt: str) -> int:
    return struct.unpack_from(fmt, raw, offset)[0]


class Ext4Struct:

    FIELDS: list[str, int, str]
    HUMAN_NAME: str

    @classmethod
    def from_bytes(cls, block: bytes) -> 'Ext4Superblock':
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
    ('i_size_high', 0x6C, LE32),
    ('i_extra_isize', 0x80, LE16),
]


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
    i_size_high: int
    i_extra_isize: int


class Ext4Filesystem:

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = None
        self.sb = None
        self.gdt: list[Ext4GroupDescriptor] = []

    def __enter__(self):
        self.fd = open(self.path, 'rb')
        # boot block is empty (1024 bytes)
        self.sb = Ext4Superblock.from_bytes(self.read_bytes(1024, 4096))
        # load the group descriptor table
        self.read_gdt()
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

    def get_root(self):
        # root inode is always the number 2
        return self.get_inode(2)

    def get_inode(self, idx: int):
        # the group of the inode
        group_idx, inode_table_entry_idx = self.get_inode_group(idx)
        # location of inode table
        inode_table_offset = self.gdt[group_idx].bg_inode_table_lo * self.sb.get_block_size()
        # location of inode in the inode table
        inode_offset = inode_table_offset + inode_table_entry_idx * self.sb.s_inode_size
        return Ext4Inode.from_bytes(self.read_bytes(inode_offset, 160))

    def get_inode_group(self, idx: int):
        # return (group_idx, inode_table_entry_idx)
        group_idx = (idx - 1) // self.sb.s_inodes_per_group
        inode_table_entry_idx = (idx - 1) % self.sb.s_inodes_per_group
        return (group_idx, inode_table_entry_idx)


if __name__ == "__main__":
    # Path to the image file
    image_file_path = 'ext4.img'

    with Ext4Filesystem(image_file_path) as e4fs:
        e4fs.sb.pretty_print()
        e4fs.gdt[0].pretty_print()
        e4fs.get_root().pretty_print()
