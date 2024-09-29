#!/usr/bin/env python3
import abc
import datetime
import enum
import struct
import dataclasses
import typing
import math
import uuid
import pwd
import grp

# --- Constants ---

EXT4MAGIC = 0xEF53
EXT4_EA_INODE_FL = 0x200000

# Precomputed for 32 bits, 0x11EDC6F41, init 0x00000000 and XOR-out 0xFFFFFFFF
CRC32C_TABLE = [
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
]

# --- Helpers ---

LE16 = '<H'
LE32 = '<L'
LE64 = '<Q'
U8 = 'B'
CHAR = 'c'


def read_little_endian(raw: bytes, offset: int, fmt: str) -> typing.Any:
    unpacked = struct.unpack_from(fmt, raw, offset)
    if len(unpacked) == 1:
        return unpacked[0]
    elif 'c' in fmt:
        return b"".join(unpacked)
    return unpacked


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

    def pretty_print(self) -> None:
        print(f'struct {self.HUMAN_NAME}:')
        assert dataclasses.is_dataclass(self)
        for f in dataclasses.fields(self.__class__):
            print(f"  {f.name}: {getattr(self, f.name)}")

# --- Superblock ---


EXT4SUPERBLOCK_FIELDS = [
    ('s_inodes_count', 0x0, LE32),
    ('s_blocks_count_lo', 0x4, LE32),
    ('s_r_blocks_count_lo', 0x8, LE32),
    ('s_free_blocks_count_lo', 0xC, LE32),
    ('s_free_inodes_count', 0x10, LE32),
    ('s_first_data_block', 0x14, LE32),
    ('s_log_block_size', 0x18, LE32),
    ('s_log_cluster_size', 0x1C, LE32),
    ('s_blocks_per_group', 0x20, LE32),
    ('s_clusters_per_group', 0x24, LE32),
    ('s_inodes_per_group', 0x28, LE32),
    ('s_mtime', 0x2C, LE32),
    ('s_wtime', 0x30, LE32),
    ('s_mnt_count', 0x34, LE16),
    ('s_max_mnt_count', 0x36, LE16),
    ('s_magic', 0x38, LE16),
    ('s_state', 0x3A, LE16),
    ('s_errors', 0x3C, LE16),
    ('s_minor_rev_level', 0x3E, LE16),
    ('s_lastcheck', 0x40, LE32),
    ('s_checkinterval', 0x44, LE32),
    ('s_creator_os', 0x48, LE32),
    ('s_rev_level', 0x4C, LE32),
    ('s_def_resuid', 0x50, LE16),
    ('s_def_resgid', 0x52, LE16),
    ('s_first_ino', 0x54, LE32),
    ('s_inode_size', 0x58, LE16),
    ('s_block_group_nr', 0x5A, LE16),
    ('s_feature_compat', 0x5C, LE32),
    ('s_feature_incompat', 0x60, LE32),
    ('s_feature_ro_compat', 0x64, LE32),
    ('s_uuid', 0x68, CHAR * 16),
    ('s_volume_name', 0x78, CHAR * 16),
    ('s_last_mounted', 0x88, CHAR * 64),
    ('s_algorithm_usage_bitmap', 0xC8, LE32),
    ('s_prealloc_blocks', 0xCC, U8),
    ('s_prealloc_dir_blocks', 0xCD, U8),
    ('s_reserved_gdt_blocks', 0xCE, LE16),
    ('s_journal_uuid', 0xD0, 'B' * 16),
    ('s_journal_inum', 0xE0, LE32),
    ('s_journal_dev', 0xE4, LE32),
    ('s_last_orphan', 0xE8, LE32),
    ('s_hash_seed', 0xEC, CHAR * 16),
    ('s_def_hash_version', 0xFC, U8),
    ('s_jnl_backup_type', 0xFD, U8),
    ('s_desc_size', 0xFE, LE16),
    ('s_default_mount_opts', 0x100, LE32),
    ('s_first_meta_bg', 0x104, LE32),
    ('s_mkfs_time', 0x108, LE32),
    ('s_jnl_blocks', 0x10C, '<LLLLLLLLLLLLLLLLL'),
    ('s_blocks_count_hi', 0x150, LE32),
    ('s_r_blocks_count_hi', 0x154, LE32),
    ('s_free_blocks_count_hi', 0x158, LE32),
    ('s_min_extra_isize', 0x15C, LE16),
    ('s_want_extra_isize', 0x15E, LE16),
    ('s_flags', 0x160, LE32),
    ('s_raid_stride', 0x164, LE16),
    ('s_mmp_interval', 0x166, LE16),
    ('s_mmp_block', 0x168, LE64),
    ('s_raid_stripe_width', 0x170, LE32),
    ('s_log_groups_per_flex', 0x174, U8),
    ('s_checksum_type', 0x175, U8),
    ('s_reserved_pad', 0x176, LE16),
    ('s_kbytes_written', 0x178, LE64),
    ('s_snapshot_inum', 0x180, LE32),
    ('s_snapshot_id', 0x184, LE32),
    ('s_snapshot_r_blocks_count', 0x188, LE64),
    ('s_snapshot_list', 0x190, LE32),
    ('s_error_count', 0x194, LE32),
    ('s_first_error_time', 0x198, LE32),
    ('s_first_error_ino', 0x19C, LE32),
    ('s_first_error_block', 0x1A0, LE64),
    ('s_first_error_func', 0x1A8, CHAR * 32),
    ('s_first_error_line', 0x1C8, LE32),
    ('s_last_error_time', 0x1CC, LE32),
    ('s_last_error_ino', 0x1D0, LE32),
    ('s_last_error_line', 0x1D4, LE32),
    ('s_last_error_block', 0x1D8, LE64),
    ('s_last_error_func', 0x1E0, CHAR * 32),
    ('s_mount_opts', 0x200, CHAR * 64),
    ('s_usr_quota_inum', 0x240, LE32),
    ('s_grp_quota_inum', 0x244, LE32),
    ('s_overhead_blocks', 0x248, LE32),
    ('s_backup_bgs', 0x24C, '<LL'),
    ('s_encrypt_algos', 0x254, CHAR * 4),
    ('s_encrypt_pw_salt', 0x258, CHAR * 16),
    ('s_lpf_ino', 0x268, LE32),
    ('s_prj_quota_inum', 0x26C, LE32),
    ('s_checksum_seed', 0x270, LE32),
    ('s_wtime_hi', 0x274, U8),
    ('s_mtime_hi', 0x275, U8),
    ('s_mkfs_time_hi', 0x276, U8),
    ('s_lastcheck_hi', 0x277, U8),
    ('s_first_error_time_hi', 0x278, U8),
    ('s_last_error_time_hi', 0x279, U8),
    ('s_pad', 0x27A, CHAR * 2),
    ('s_encoding', 0x27C, LE16),
    ('s_encoding_flags', 0x27E, LE16),
    ('s_orphan_file_inum', 0x280, LE32),
    ('s_reserved', 0x284, '<' + 'L' * 94),
    ('s_checksum', 0x3FC, LE32)
]


@dataclasses.dataclass
class Ext4Superblock(Ext4Struct):

    FIELDS = EXT4SUPERBLOCK_FIELDS
    HUMAN_NAME = 'ext4_super_block'

    s_inodes_count: int
    s_blocks_count_lo: int
    s_r_blocks_count_lo: int
    s_free_blocks_count_lo: int
    s_free_inodes_count: int
    s_first_data_block: int
    s_log_block_size: int
    s_log_cluster_size: int
    s_blocks_per_group: int
    s_clusters_per_group: int
    s_inodes_per_group: int
    s_mtime: int
    s_wtime: int
    s_mnt_count: int
    s_max_mnt_count: int
    s_magic: int
    s_state: int
    s_errors: int
    s_minor_rev_level: int
    s_lastcheck: int
    s_checkinterval: int
    s_creator_os: int
    s_rev_level: int
    s_def_resuid: int
    s_def_resgid: int
    s_first_ino: int
    s_inode_size: int
    s_block_group_nr: int
    s_feature_compat: int
    s_feature_incompat: int
    s_feature_ro_compat: int
    s_uuid: uuid.UUID
    s_volume_name: bytes
    s_last_mounted: bytes
    s_algorithm_usage_bitmap: int
    s_prealloc_blocks: int
    s_prealloc_dir_blocks: int
    s_reserved_gdt_blocks: int
    s_journal_uuid: bytes
    s_journal_inum: int
    s_journal_dev: int
    s_last_orphan: int
    s_hash_seed: uuid.UUID
    s_def_hash_version: int
    s_jnl_backup_type: int
    s_desc_size: int
    s_default_mount_opts: int
    s_first_meta_bg: int
    s_mkfs_time: int
    s_jnl_blocks: bytes
    s_blocks_count_hi: int
    s_r_blocks_count_hi: int
    s_free_blocks_count_hi: int
    s_min_extra_isize: int
    s_want_extra_isize: int
    s_flags: int
    s_raid_stride: int
    s_mmp_interval: int
    s_mmp_block: int
    s_raid_stripe_width: int
    s_log_groups_per_flex: int
    s_checksum_type: int
    s_reserved_pad: int
    s_kbytes_written: int
    s_snapshot_inum: int
    s_snapshot_id: int
    s_snapshot_r_blocks_count: int
    s_snapshot_list: int
    s_error_count: int
    s_first_error_time: int
    s_first_error_ino: int
    s_first_error_block: int
    s_first_error_func: bytes
    s_first_error_line: int
    s_last_error_time: int
    s_last_error_ino: int
    s_last_error_line: int
    s_last_error_block: int
    s_last_error_func: bytes
    s_mount_opts: bytes
    s_usr_quota_inum: int
    s_grp_quota_inum: int
    s_overhead_blocks: int
    s_backup_bgs: bytes
    s_encrypt_algos: bytes
    s_encrypt_pw_salt: bytes
    s_lpf_ino: int
    s_prj_quota_inum: int
    s_checksum_seed: int
    s_wtime_hi: int
    s_mtime_hi: int
    s_mkfs_time_hi: int
    s_lastcheck_hi: int
    s_first_error_time_hi: int
    s_last_error_time_hi: int
    s_pad: bytes
    s_encoding: int
    s_encoding_flags: int
    s_orphan_file_inum: int
    s_reserved: bytes
    s_checksum: int

    def __post_init__(self) -> None:
        # Ensure correct magic number
        if self.s_magic != EXT4MAGIC:
            raise ValueError(f'no ext4 superblock: invalid magic number {self.s_magic}')

        # Remove null termination from byte string
        self.s_last_mounted = self.s_last_mounted.rstrip(b'\x00')

        # Transform raw bytes to UUID for s_uuid
        if isinstance(self.s_uuid, bytes):
            self.s_uuid = uuid.UUID(bytes=self.s_uuid)

        # Transform raw bytes to UUID for s_hash_seed
        if isinstance(self.s_hash_seed, bytes):
            self.s_hash_seed = uuid.UUID(bytes=self.s_hash_seed)

    def get_block_size(self) -> int:
        return int(2 ** (10 + self.s_log_block_size))


class CompatFeature(enum.IntFlag):
    DIR_PREALLOC = 0x1                # Directory preallocation
    IMAGIC_INODES = 0x2               # "imagic inodes"
    HAS_JOURNAL = 0x4                 # Has a journal
    EXT_ATTR = 0x8                    # Supports extended attributes
    RESIZE_INODE = 0x10               # Has reserved GDT blocks for filesystem expansion
    DIR_INDEX = 0x20                  # Has directory indices
    LAZY_BG = 0x40                    # "Lazy BG" for uninitialized block groups
    EXCLUDE_INODE = 0x80              # "Exclude inode"
    EXCLUDE_BITMAP = 0x100            # "Exclude bitmap" for snapshot-related exclude bitmaps
    SPARSE_SUPER2 = 0x200             # Sparse Super Block, v2
    FAST_COMMIT = 0x400               # Fast commits supported
    ORPHAN_FILE = 0x1000              # Orphan file allocated


class IncompatFeature(enum.IntFlag):
    COMPRESSION = 0x1                      # Compression
    FILETYPE = 0x2                         # Directory entries record the file type
    RECOVER = 0x4                          # Filesystem needs recovery
    JOURNAL_DEV = 0x8                      # Filesystem has a separate journal device
    META_BG = 0x10                         # Meta block groups
    EXTENTS = 0x40                         # Files in this filesystem use extents
    BIT_64 = 0x80                          # Enable a filesystem size of 2^64 blocks
    MMP = 0x100                            # Multiple mount protection
    FLEX_BG = 0x200                        # Flexible block groups
    EA_INODE = 0x400                       # Inodes can store large extended attribute values
    DIRDATA = 0x1000                       # Data in directory entry (not implemented?)
    CSUM_SEED = 0x2000                     # Metadata checksum seed stored in the superblock
    LARGEDIR = 0x4000                      # Large directory >2GB or 3-level htree
    INLINE_DATA = 0x8000                   # Data in inode
    ENCRYPT = 0x10000


class RoCompatFeature(enum.IntFlag):
    SPARSE_SUPER = 0x1                  # Sparse superblocks
    LARGE_FILE = 0x2                    # File > 2GiB
    BTREE_DIR = 0x4                     # Not used (RO_COMPAT_BTREE_DIR)
    HUGE_FILE = 0x8                     # Files use units of logical blocks (RO_COMPAT_HUGE_FILE)
    GDT_CSUM = 0x10                     # Group descriptors have checksums (RO_COMPAT_GDT_CSUM)
    DIR_NLINK = 0x20                    # Old ext3 subdirectory limit no longer applies (RO_COMPAT_DIR_NLINK)
    EXTRA_ISIZE = 0x40                  # Large inodes exist on the filesystem (RO_COMPAT_EXTRA_ISIZE)
    HAS_SNAPSHOT = 0x80                 # Filesystem has a snapshot (RO_COMPAT_HAS_SNAPSHOT)
    QUOTA = 0x100                       # Quota support (RO_COMPAT_QUOTA)
    BIGALLOC = 0x200                    # Filesystem supports "bigalloc" (RO_COMPAT_BIGALLOC)
    METADATA_CSUM = 0x400               # Metadata checksumming supported (RO_COMPAT_METADATA_CSUM)
    REPLICA = 0x800                     # Filesystem supports replicas (RO_COMPAT_REPLICA)
    READONLY = 0x1000                   # Read-only filesystem image (RO_COMPAT_READONLY)
    PROJECT = 0x2000                    # Filesystem tracks project quotas (RO_COMPAT_PROJECT)
    VERITY = 0x8000                     # Verity inodes may be present (RO_COMPAT_VERITY)
    ORPHAN_PRESENT = 0x10000


class Ext4DefMountOpt(enum.IntFlag):
    DEBUG = 0x0001                        # Print debugging info upon (re)mount
    BSDGROUPS = 0x0002                    # New files take the gid of the containing directory
    XATTR_USER = 0x0004                   # Support userspace-provided extended attributes
    ACL = 0x0008                          # Support POSIX access control lists (ACLs)
    UID16 = 0x0010                        # Do not support 32-bit UIDs
    JMODE_DATA = 0x0020                   # All data and metadata are committed to the journal
    JMODE_ORDERED = 0x0040                # All data are flushed before metadata is committed to the journal
    JMODE_WBACK = 0x0060                  # Data ordering is not preserved; may be written after metadata
    NOBARRIER = 0x0100                    # Disable write flushes
    BLOCK_VALIDITY = 0x0200               # Track which blocks are metadata
    DISCARD = 0x0400                      # Enable DISCARD support
    NODELALLOC = 0x0800                   # Disable delayed allocation


class HashAlgorithm(enum.IntEnum):
    LEGACY = 0x0
    HALF_MD4 = 0x1
    TEA = 0x2
    LEGACY_UNSIGNED = 0x3
    HALF_MD4_UNSIGNED = 0x4
    TEA_UNSIGNED = 0x5


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
        return f"{self.__class__.__name__}({self.name}={self.value!r})"

    def __bool__(self) -> bool:
        return bool(self.e_name_len | self.e_name_index | self.e_value_offs)


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

    def __repr__(self) -> str:
        return f'Inode(i_num={self.i_num}, offset={self.offset})'

    @property
    def is_file(self) -> bool:
        return self.file_type == InodeFileType.S_IFREG

    @property
    def is_dir(self) -> bool:
        return self.file_type == InodeFileType.S_IFDIR

    @property
    def size(self) -> int:
        return self.e4inode.i_size_high << 32 | self.e4inode.i_size_lo

    def read(self) -> bytes:
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

    def close(self) -> None:
        self.fd.close()
        del self.fd

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        self.fd.close()

    def read_bytes(self, offset: int, length: int) -> bytes:
        self.fd.seek(offset)
        b = self.fd.read(length)
        return b

    def read_blocks(self, i: int, n: int) -> bytes:
        # Read N block beginning at block i
        return self.read_bytes(i * self.sb.get_block_size(), n * self.sb.get_block_size())

    def read_gdt(self) -> None:
        # Fill the group descriptor table
        self.gdt = []
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

    def get_inode_group(self, idx: int) -> tuple[int, int]:
        # return (group_idx, inode_table_entry_idx)
        group_idx = (idx - 1) // self.sb.s_inodes_per_group
        inode_table_entry_idx = (idx - 1) % self.sb.s_inodes_per_group
        return (group_idx, inode_table_entry_idx)

    def get_xattrs(self, inode: Inode) -> typing.Generator[Ext4XattrEntry, None, None]:
        # Read extended attributes (xattrs) for this inode.
        def read(data: bytes, i: int) -> typing.Generator[Ext4XattrEntry, None, None]:
            while i < len(data):
                xattr = Ext4XattrEntry.from_bytes(data[i:])
                xattr.e_name = data[0x10 + i: 0x10 + i + xattr.e_name_len]

                if not xattr:
                    # End of xattr list
                    return

                if xattr.e_value_inum != 0:
                    # value is stored in a different inode
                    xattr_inode = self.get_inode(xattr.e_value_inum)
                    assert xattr_inode.e4inode.i_flags & EXT4_EA_INODE_FL == 0
                    value_buffer = xattr_inode.read()[xattr.e_value_offs: xattr.e_value_offs + xattr.e_value_size + 1]
                else:
                    # value is stored in the same inode
                    value_buffer = data[xattr.e_value_offs: xattr.e_value_offs + xattr.e_value_size + 1]

                # Extract value (null terminated)
                j = -1
                for j, b in enumerate(value_buffer):
                    if b == 0:
                        break

                if j == -1:
                    raise ValueError('xattr not null terminated')

                xattr.value = value_buffer[:j]

                yield xattr

                # Calculate the entry size and round up to the nearest 4-byte boundary
                entry_size = 16 + xattr.e_name_len + 1  # base size + name + null terminator
                entry_size_aligned = math.ceil(entry_size / 4) * 4
                i += entry_size_aligned

        # There are two places where extended attributes can be found.
        # The first place is between the end of each inode entry and the beginning of the next inode entry.
        # Calculate the available bytes for in-inode storage.
        avail = self.sb.s_inode_size - (128 + inode.e4inode.i_extra_isize)
        if avail > 0:
            data = self.read_bytes(inode.offset + 128 + inode.e4inode.i_extra_isize, avail)
            if data[0:4] == b"\x00\x00\x02\xea":
                # magic number: 0xEA020000 (ext4_xattr_ibody_header)
                yield from read(data[4:], 0)

        # The second place where extended attributes can be found is pointed to by inode.i_file_acl.
        if inode.e4inode.i_file_acl_lo != 0:
            data = self.read_blocks(inode.e4inode.i_file_acl_lo, 1)
            header = Ext4XattrHeader.from_bytes(data)
            assert header.h_magic == 0xEA020000
            yield from read(data, 32)

    def compute_checksum(self) -> int:
        # Read the first 1024 bytes (size of superblock)
        data = self.read_bytes(1024, 1024)
        # Exclude the checksum
        data = data[:0x3FC]
        return cr32c(data, 0xFFFFFFFF)

    @property
    def checksum_valid(self) -> bool:
        return self.compute_checksum() == self.sb.s_checksum


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
    name: bytes = dataclasses.field(init=False)

    @classmethod
    def from_bytes(cls: typing.Type['Ext4DirEntry2'], block: bytes) -> 'Ext4DirEntry2':
        de = super().from_bytes(block[:8])
        de.name = block[8: 8 + de.name_len]
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
            # TODO
            return InlineByteStream(inode)  # type: ignore
        else:
            raise ValueError('can only read extents or inline data')

    @abc.abstractmethod
    def iter_blocks(self) -> typing.Generator[int, None, None]:
        pass

    def read_blocks(self, blocks: int = -1) -> typing.Generator[bytes, None, None]:
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

    def read(self) -> bytes:
        return b"".join(self.read_blocks(-1))


class ExtentByteStream(ByteStream):

    def iter_blocks(self) -> typing.Generator[int, None, None]:
        """Yield consecutive number of blocks for this extent.
        e.g.: [15, 16, 17, ...]"""

        def traverse_extent_tree(block_data: bytes, depth: int) -> typing.Generator[int, None, None]:
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


def human_mode(mode: int) -> str:
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


#
# Commands
#

def ls(root: Inode) -> None:
    for entry in root.iter():
        # .rwxrwxrwx root root 12301 Jul 13 11:01 test.file
        inode = root.filesystem.get_inode(entry.inode)
        prefix = 'd' if inode.is_dir else '.'
        mode = human_mode(inode.e4inode.i_mode)
        size = inode.e4inode.i_size_high << 32 | inode.e4inode.i_size_lo
        mtime = datetime.datetime.fromtimestamp(inode.e4inode.i_mtime)

        print(f'{prefix}{mode} {inode.e4inode.i_uid} {inode.e4inode.i_gid} {size} {mtime.isoformat()} {entry.name.decode()}')


def cat(root: Inode) -> None:
    if not root.is_file:
        raise TypeError('can only cat files')
    print(root.read().decode(), end='')


def get_features(sb: Ext4Superblock) -> typing.Generator[str | None, None, None]:
    for cf in CompatFeature:
        if cf & sb.s_feature_compat:
            yield cf.name

    for icf in IncompatFeature:
        if icf & sb.s_feature_incompat:
            yield icf.name

    for rcf in RoCompatFeature:
        if rcf & sb.s_feature_ro_compat:
            yield rcf.name


def get_mount_opts(sb: Ext4Superblock) -> typing.Generator[str | None, None, None]:
    for opt in Ext4DefMountOpt:
        if opt & sb.s_default_mount_opts:
            yield opt.name


def format_time(ts: int) -> str:
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime('%a %b %d %H:%M:%S %Y')


def get_username_by_uid(uid: int) -> str:
    """Return the username for a given user ID."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return 'unknown'


def get_group_by_uid(uid: int) -> str:
    """Return the group for a given ID."""
    try:
        return grp.getgrgid(uid).gr_name
    except KeyError:
        return 'unknown'


def tunefs(fs: Ext4Filesystem) -> dict[str, typing.Any]:
    sb = fs.sb
    return {
        "Last mounted on": sb.s_last_mounted.decode(),
        "Filesystem UUID": str(sb.s_uuid),
        "Filesystem magic number": hex(sb.s_magic),
        "Filesystem revision": sb.s_rev_level,
        "Filesystem features": ' '.join(map(str, get_features(sb))),
        "Default mount options": ' '.join(map(str, get_mount_opts(sb))),
        "Filesystem state": "clean" if sb.s_state == 1 else "unknown",
        "Errors behavior": "Continue" if sb.s_errors == 1 else "Unknown",
        "Filesystem OS type": "Linux" if sb.s_creator_os == 0 else "Unknown",
        "Inode count": sb.s_inodes_count,
        "Block count": sb.s_blocks_count_lo + (sb.s_blocks_count_hi << 32),
        "Reserved block count": sb.s_r_blocks_count_lo + (sb.s_r_blocks_count_hi << 32),
        "Overhead clusters": sb.s_overhead_blocks,
        "Free blocks": sb.s_free_blocks_count_lo + (sb.s_free_blocks_count_hi << 32),
        "Free inodes": sb.s_free_inodes_count,
        "First block": sb.s_first_data_block,
        "Block size": sb.get_block_size(),
        "Fragment size": 1024 << sb.s_log_cluster_size,
        "Group descriptor size": sb.s_desc_size,
        "Reserved GDT blocks": sb.s_reserved_gdt_blocks,
        "Blocks per group": sb.s_blocks_per_group,
        "Fragments per group": sb.s_clusters_per_group,
        "Inodes per group": sb.s_inodes_per_group,
        "Inode blocks per group": (sb.s_inodes_per_group * sb.s_inode_size + sb.get_block_size() - 1) // sb.get_block_size(),
        "Flex block group size": sb.s_log_groups_per_flex,
        "Filesystem created": format_time(sb.s_mkfs_time),
        "Last mount time": format_time(sb.s_mtime),
        "Last write time": format_time(sb.s_wtime),
        "Mount count": sb.s_mnt_count,
        "Maximum mount count": sb.s_max_mnt_count,
        "Last checked": format_time(sb.s_lastcheck),
        "Check interval": "0 (<none>)",
        "Lifetime writes": f"{sb.s_kbytes_written // 1024} MB",
        "Reserved blocks uid": f"{sb.s_def_resuid} (user {get_username_by_uid(sb.s_def_resuid)})",
        "Reserved blocks gid": f"{sb.s_def_resgid} (group {get_group_by_uid(sb.s_def_resgid)})",
        "First inode": sb.s_first_ino,
        "Inode size": sb.s_inode_size,
        "Required extra isize": sb.s_min_extra_isize,
        "Desired extra isize": sb.s_want_extra_isize,
        "Journal inode": sb.s_journal_inum,
        "Default directory hash": HashAlgorithm(sb.s_def_hash_version).name,
        "Directory Hash Seed": str(sb.s_hash_seed),
        "Journal backup": 'inode blocks' if sb.s_jnl_backup_type == 1 else 'Unknown',  # TODO: not sure
        "Checksum type": 'crc32c' if sb.s_checksum_type else 'Invalid',
        "Checksum": hex(sb.s_checksum)  # TODO: how to calculate & verify the checksum?
    }


def cr32c(data: bytes, crc: int) -> int:
    """Computes a CRC32C checksum (reverse).
    >>>cr32c(b"123456789")
    0xE3069283
    """
    crc = crc & 0xFFFFFFFF
    for x in data:
        crc = CRC32C_TABLE[x ^ (crc & 0xFF)] ^ (crc >> 8)
    return crc
