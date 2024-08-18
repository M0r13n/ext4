import pathlib
import os
from .base import BaseTestCase, EXT4_MNT_PATH, EXT4_IMG_PATH, get_inode


def create_file_with_xattrs(file, xattrs) -> pathlib.Path:
    # Creates a file with extended attributes.
    file.unlink(True)
    file.touch()
    for k, v in xattrs:
        os.setxattr(file, k, v)
    os.sync()
    return file


class XattrTestCase(BaseTestCase):
    FILES = [
        EXT4_MNT_PATH.joinpath('file.xattr'),
    ]

    @property
    def file(self):
        return self.FILES[0]

    def test_single(self):
        create_file_with_xattrs(self.file, [("user.foo", b"bar")])
        inode = get_inode(self.fs, self.file)
        xattrs = list(self.fs.get_xattrs(inode))

        self.assertEqual(len(xattrs), 1)
        self.assertEqual(xattrs[0].name, "user.foo")
        self.assertEqual(xattrs[0].value, b"bar")

    def test_multiple(self):
        xattrs_in = [("user.foo", b"bar"), ("user.bar", b"42"), ("user.baz", b"Hello, World!!")]
        create_file_with_xattrs(self.file, xattrs_in)
        inode = get_inode(self.fs, self.file)
        xattrs_out = list(self.fs.get_xattrs(inode))

        self.assertEqual(len(xattrs_out), 3)
        self.assertEqual(sorted([(x.name, x.value) for x in xattrs_out]), sorted(xattrs_in))

    def test_large(self):
        create_file_with_xattrs(self.file, [("user.foo", b"F" * 4000)])
        inode = get_inode(self.fs, self.file)
        xattrs = list(self.fs.get_xattrs(inode))

        self.assertEqual(len(xattrs), 1)
        self.assertEqual(xattrs[0].name, "user.foo")
        self.assertEqual(xattrs[0].value, b"F" * 3999)
