
import os


with open('/mnt/ext4/large.file', 'w') as fd:
    fd.truncate(500000000)
    fd.seek(500000000)
    fd.write('Banana!')
    fd.flush()
    os.sync()
