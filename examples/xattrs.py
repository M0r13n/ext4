#!/bin/env python
import os
import pathlib
import sys

from ext4 import Ext4DirEntry2, Ext4Filesystem, Inode, ls, cat, Ext4XattrEntry, EXT4_XATTR_PREFIXES

MNT_POINT = pathlib.Path('/mnt/ext4')


def create_file_with_xattrs() -> pathlib.Path:
    # Creates a file with extended attributes.
    # Sets user.comment to "Hello, World!"
    # Verify with: getfattr -d -m '' /mnt/ext4/file.xattr
    file = MNT_POINT.joinpath('file.xattr')
    file.touch()
    os.setxattr(file, 'user.comment', b'Hello, World!')
    os.setxattr(file, 'user.comment_2', b'Foo Foo')
    os.setxattr(file, 'user.comment_3', b'42')
    return file


def get_inode(fs: Ext4Filesystem, file: pathlib.Path) -> Inode:
    # Get the inode for a given path from the filesystem.
    root = fs.get_root()
    for de in root.iter():
        if de.name.decode() == file.name:
            return fs.get_inode(de.inode)
    raise FileNotFoundError(file)


def main():
    with Ext4Filesystem('ext4.img') as fs:
        file = create_file_with_xattrs()
        inode = get_inode(fs, file)

        for attr in fs.get_xattrs(inode):
            print(attr)


if __name__ == '__main__':
    main()
