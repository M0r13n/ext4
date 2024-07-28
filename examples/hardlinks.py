
import os
import pathlib
import sys


try:
    sys.path.append(pathlib.Path(__file__).parent.parent.as_posix())
    from ext4 import Ext4Filesystem, ls, cat
except ImportError:
    raise


def make_hardlink():
    # Create a hard link
    orig = pathlib.Path('/mnt/ext4/orig.file')
    link = orig.parent.joinpath('orig.hardlink')

    with open(orig, 'wb') as fd:
        fd.write(b'I like Linux!\n')

    if not link.exists():
        link.hardlink_to(orig)
    os.sync()
    return orig, link


def main():
    orig, link = make_hardlink()
    orig_entry, link_entry = None, None

    # Path to the image file
    image_file_path = 'ext4.img'

    try:

        with Ext4Filesystem(image_file_path) as e4fs:
            root = e4fs.get_root()

            # ls like iteration
            ls(root)

            for file in root.iter():
                fname = file.name.decode()
                if fname == orig.name:
                    orig_entry = file
                if fname == link.name:
                    link_entry = file

            # Hard links are directory entries pointing to the name Inode
            assert orig_entry.inode == link_entry.inode

            # Read contents
            inode = e4fs.get_inode(orig_entry.inode)
            cat(inode)

            # Delete the original file
            orig.unlink()
            os.sync()

            # Read contents again
            cat(inode)
    finally:
        # Cleanup
        orig.unlink(missing_ok=True)
        link.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
