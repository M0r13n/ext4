import pathlib
import unittest
import os

from ext4 import Ext4Filesystem, Inode

EXT4_IMG_PATH = pathlib.Path(__file__).parent.parent.joinpath('ext4.img')
EXT4_MNT_PATH = pathlib.Path('/mnt/ext4')


def get_inode(fs: Ext4Filesystem, file: pathlib.Path) -> Inode:
    # Get the inode for a given path from the filesystem.
    root = fs.get_root()
    for de in root.iter():
        if de.name.decode() == file.name:
            return fs.get_inode(de.inode)
    raise FileNotFoundError(file)


class BaseTestCase(unittest.TestCase):

    FILES = []

    @classmethod
    def setUpClass(cls) -> None:
        cls.check_precon()
        # Create all files
        for file in cls.FILES:
            if not file.exists():
                file.touch()

        # The OS might take some time to sync
        os.sync()
        cls.fs = Ext4Filesystem(EXT4_IMG_PATH)

    @staticmethod
    def check_precon():
        # Check preconditions (e.g. mounted volume)
        if not EXT4_IMG_PATH.exists():
            raise FileNotFoundError(f'{EXT4_IMG_PATH} not found. Did you run "./scripts/create_virtual_fs.sh"?')

        if not EXT4_MNT_PATH.exists():
            raise FileNotFoundError(f'{EXT4_MNT_PATH} not found. Did you run "./scripts/create_virtual_fs.sh"?')

        try:
            test = EXT4_MNT_PATH.joinpath('test.test')
            test.touch()
            test.unlink()
        except PermissionError as err:
            raise PermissionError(
                'Can not read/write to test path. Did you run "./scripts/create_virtual_fs.sh"?'
            ) from err

    @classmethod
    def tearDownClass(cls) -> None:
        # Cleanup and remove artifacts
        # Create all files
        for file in cls.FILES:
            file.unlink(True)
        cls.fs.close()
