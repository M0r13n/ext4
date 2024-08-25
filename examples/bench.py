import sys
import time
import pathlib


from ext4 import Ext4Filesystem, ByteStream

FILE = pathlib.Path('/mnt/ext4/large.file')


def read_native():
    # Read the file using the OS file system implementation
    start = time.time()
    bytes_read = 0
    with open(FILE, 'rb') as fd:
        while True:
            chunk = fd.read(1024)
            bytes_read += len(chunk)
            if not chunk:
                break
    print(f'Native read ({bytes_read} bytes) took: {time.time() - start:.2f}s')


def read_python():
    # Read the file using this implementation in user space
    with Ext4Filesystem('ext4.img') as fs:

        # Get the file
        root = fs.get_root()
        for file in root.iter():
            if file.name.decode() == FILE.name:
                break
        else:
            raise FileNotFoundError(FILE)
        inode = fs.get_inode(file.inode)

        start = time.time()
        bytes_read = 0

        stream = ByteStream.create(inode)

        for chunk in stream.read_blocks():
            bytes_read += len(chunk)

        print(f'User space read ({bytes_read} bytes) took: {time.time() - start:.2f}s')


def ensure_file_exists():
    if not FILE.exists():
        print(
            'Create the file first with: "dd if=/dev/urandom of=largefile bs=1M count=10000 of=/mnt/ext4/large.file"'
        )
        sys.exit(1)


if __name__ == "__main__":
    ensure_file_exists()
    read_native()
    read_python()
