import os
import pathlib
import sys

from ext4 import Ext4DirEntry2, Ext4Filesystem, Inode, ls, cat

MNT_POINT = pathlib.Path('/mnt/ext4')


def create_nested_directory_structure() -> pathlib.Path:
    # NOTE: the absolute path as seen from the OS is different from the absolute file on the image file.
    # This method creates a file using the OS and requires the absolute path.
    # The method returns the path on the image.
    long_path = pathlib.Path('some/relatively/long/path/super.file')
    abs_path = MNT_POINT.joinpath(long_path)
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.touch()
    return long_path


def get_entry(fs: Ext4Filesystem, path: pathlib.Path) -> Ext4DirEntry2:
    # Get the dir entry for a given path by traversing the hierarchical structure.
    # Each part of the path is resolved step by step.
    # Each step involves reading the relevant disk blocks that contain directory entries.
    # May raise a FileNotFoundError.
    cur, nxt, entry = fs.get_root(), None, None
    parts = path.parts
    for part in parts:
        if part == '':
            # skip root
            continue

        nxt = None
        for entry in cur.iter():
            if entry.name.decode() == part:
                nxt = fs.get_inode(entry.inode)
                break

        if nxt is None:
            raise FileNotFoundError(path)

        cur = nxt

    if entry is None:
        raise FileNotFoundError(path)
    return entry


def main():
    with Ext4Filesystem('ext4.img') as e4fs:
        path = create_nested_directory_structure()
        entry = get_entry(e4fs, path)
        print(entry)

        try:
            _ = get_entry(e4fs, pathlib.Path('does/not/exist'))
        except FileNotFoundError as err:
            print(err)

        try:
            _ = get_entry(e4fs, pathlib.Path('some/relatively/long/path/foo.bar'))
        except FileNotFoundError as err:
            print(err)


if __name__ == '__main__':
    main()
