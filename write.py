with open('/mnt/ext4/large.file', 'w') as fd:
    fd.write(" ".join(map(str, range(100000000))))
