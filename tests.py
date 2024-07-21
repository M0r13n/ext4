import functools
import os
import pathlib
import shutil
import sys
import unittest

from ext4 import Ext4Filesystem

EXT4_IMG_PATH = pathlib.Path(__file__).parent.joinpath('ext4.img')
EXT4_MNT_PATH = pathlib.Path('/mnt/ext4')


class BaseTestCase(unittest.TestCase):

    FILES = []

    @classmethod
    def setUpClass(cls) -> None:
        # Create all files
        for file in cls.FILES:
            if not file.exists():
                file.touch()

        # The OS might take some time to sync
        os.sync()
        cls.fs = Ext4Filesystem(EXT4_IMG_PATH)

    @classmethod
    def tearDownClass(cls) -> None:
        # Cleanup and remove artifacts
        # Create all files
        for file in cls.FILES:
            file.unlink(True)
        cls.fs.close()


class Ext4ReadRootTestCase(BaseTestCase):
    FILES = [
        EXT4_MNT_PATH.joinpath('foo.bar'),
        EXT4_MNT_PATH.joinpath('bla.bar'),
    ]

    def test_root_is_directory(self):
        self.assertTrue(self.fs.get_root().is_dir)

    def test_root_contains_at_least_foo_and_bla(self):
        root = self.fs.get_root()
        contents = [c for c in root.iter()]
        names = [e.name.decode() for e in contents]

        self.assertTrue(len(contents) >= 4)
        self.assertTrue('.' in names)
        self.assertTrue('..' in names)
        self.assertTrue('foo.bar' in names)
        self.assertTrue('bla.bar' in names)


class SmallFileReadTestCase(BaseTestCase):

    FILES = [
        EXT4_MNT_PATH.joinpath('foo.bar'),
    ]

    def test_that_a_small_file_can_be_read(self):
        with open(self.FILES[0], 'w') as fd:
            fd.write('Hello, World!')
            fd.flush()
            os.sync()

        root = self.fs.get_root()
        file = next(entry for entry in root.iter() if entry.name.decode() == 'foo.bar')
        inode = self.fs.get_inode(file.inode)
        content = inode.read().decode()

        self.assertEqual(content, "Hello, World!")


class LargeFileReadTestCase(BaseTestCase):

    FILES = [
        EXT4_MNT_PATH.joinpath('foo.bar'),
    ]

    def test_that_a_large_file_can_be_read(self):

        with open(self.FILES[0], 'w') as fd:
            fd.truncate(500000000)
            fd.seek(500000000)
            fd.write('Banana!')
            fd.flush()
            os.sync()

        fs = Ext4Filesystem(EXT4_IMG_PATH)
        root = fs.get_root()
        file = next(entry for entry in root.iter() if entry.name.decode() == 'foo.bar')
        inode = fs.get_inode(file.inode)
        content = inode.read().decode()

        self.assertEqual(inode.size, 500000007)
        self.assertEqual(content[-20:], "Banana!")


# Utils


def die(msg: str, code: int = 1) -> str:
    print(msg, file=sys.stderr)
    sys.exit(code)


def delete_all(directory: pathlib.Path) -> None:
    if not directory.relative_to('/mnt'):
        raise ValueError('won\'t rm anything other than /mnt')

    for path in directory.glob("**/*"):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def setup():
    if not EXT4_IMG_PATH.exists() or not EXT4_MNT_PATH.exists():
        die('Image or Mountpoint not found. Make sure to run "./scripts/create_virtual_fs.sh".')


if __name__ == '__main__':
    setup()
    unittest.main()
