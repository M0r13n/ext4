# https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html#super-block
#!/usr/bin/env python3
import struct
import dataclasses

# --- Constants ---

EXT4MAGIC = 0xEF53
BLOCKSIZE = 1024

# --- Helpers ---

LE16 = '<H'
LE32 = '<L'
U8 = 'B'


def read_little_endian(raw: bytes, offset: int, fmt: str) -> int:
    return struct.unpack_from(fmt, raw, offset)[0]

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
]


@dataclasses.dataclass
class Ext4Superblock:
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

    def __post_init__(self):
        if self.s_magic != EXT4MAGIC:
            raise ValueError(f'no ext4 superblock: invalid magic number {self.s_magic}')

    @classmethod
    def from_bytes(cls, block: bytes) -> 'Ext4Superblock':
        kwargs = {}
        for attr, offset, size in EXT4SUPERBLOCK_FIELDS:
            kwargs[attr] = read_little_endian(block, offset, size)
        return cls(**kwargs)

    def pretty_print(self):
        print('struct ext4_super_block:')
        for f in dataclasses.fields(self):
            print(f"  {f.name}: {getattr(self, f.name)}")

    def get_block_size(self) -> int:
        return 2 ** (10 + self.s_log_block_size)

    def get_block(self, index, n=1):
        return self.get_bytes(index * self.conf.get_block_size(), n * self.conf.get_block_size())


@dataclasses.dataclass
class Ext4BlockGroupDescriptor:
    pass


class Ext4Inode:
    pass


class Ext4Filesystem:

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = None
        self.sb = None

    def __enter__(self):
        self.fd = open(self.path, 'rb')
        # first block is empty (boot block)
        self.sb = Ext4Superblock.from_bytes(self.read_bytes(BLOCKSIZE, BLOCKSIZE))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fd.close()

    def read_bytes(self, offset, length):
        self.fd.seek(offset)
        b = self.fd.read(length)
        return b

    def read_blocks(self, i, n):
        return self.read_bytes(i * self.sb.get_block_size(), n * self.sb.get_block_size())

    def read_bgd(self, block_group):
        # TODO: is this correct?
        bgd_size = 32
        superblock_size = 1
        block_no = superblock_size + (block_group // bgd_per_block)
        offset_in_block = bg_no % bgd_per_block * bgd_size
        bgd_pos = block_no * self.conf.get_block_size() + offset_in_block


if __name__ == "__main__":
    # Path to the image file
    image_file_path = 'ext4.img'

    with Ext4Filesystem(image_file_path) as e4fs:
        e4fs.sb.pretty_print()
