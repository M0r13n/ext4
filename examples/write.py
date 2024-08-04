
import os
import pathlib
import sys

from ext4 import Ext4Filesystem, ls


with open('/mnt/ext4/large.file', 'wb') as fd:
    fd.write(b'\x00' * 500000000)
    fd.write(b'Banana!')
    fd.flush()
    os.sync()


def main():
    # Path to the image file
    image_file_path = 'ext4.img'

    with Ext4Filesystem(image_file_path) as e4fs:
        root = e4fs.get_root()

        # ls like iteration
        ls(root)

        last = list(root.iter())[-1]
        inode = e4fs.get_inode(last.inode)
        content = inode.read().decode()
        print(content[-100:])
        print(len(content))


if __name__ == "__main__":
    main()
