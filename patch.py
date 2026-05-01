#!/usr/bin/env python3

import hashlib
import os
import stat
import subprocess
import sys


def hashfile(data):
    return hashlib.sha1(data).hexdigest()


VERSIONS = [
    # (name, input_sha1, output_sha1)
    ("1.3.3-4build1 (Ubuntu 22)", "b7a18df897cff95d52f6d3ec279c7b1d2caf798b", "e6cb221fca7f511eb91b1bb2fa6ea86347bf1fce"),
]

PATCHES = [
    # current lastpass.com primary (leaf)
    (b"0hkr5YW/WE6Nq5hNTcApxpuaiwlwy5HUFiOt3Qd9VBc=", b"YDjIAXSYj+mh+25FGifAiKN4oNOAj+as6gQv4naQG0M="),
    # current lastpass.eu primary (leaf)
    (b"8CzY4qWQKZjFDwHXTOIpsVfWkiVnrhQOJEM4Q2b2Ar4=", b"SjMnNhjAyVM5Yv6O5JaQgNygBTU0wdb8Jz3mfQfTc28="),
    # GlobalSign ECC OV SSL CA 2018 intermediate CA
    (b"SQAWwwYXoceSd8VNbiyxspGXEjFndkklEO2XzLMts10=", b"OD/WDbD3VsfMwwNzzy9MWd9JXppKB77Vb3ST2wn9meg="),
]


def main(filename):
    with open(filename, "rb") as fh:
        orig_bin = fh.read()
    current_hash = hashfile(orig_bin)

    print("Detecting lpass version...")
    expected_output_hash = None
    for name, input_hash, output_hash in VERSIONS:
        if input_hash == current_hash:
            print("Detected version %s, with hash %s" % (name, input_hash))
            expected_output_hash = output_hash
            break
    else:
        print("Unknown version with hash %s" % (current_hash,))
        sys.exit(1)

    print("Backing up original binary...")
    with open(filename + ".original.bak", "wb") as fh:
        fh.write(orig_bin)

    print("Creating patch...")
    new_bin = orig_bin
    for old_pk, new_pk in PATCHES:
        new_bin = new_bin.replace(old_pk, new_pk)

    print("Verifying patch...")
    assert hashfile(new_bin) == expected_output_hash, "Patch verification failed, not patching"
    with open(filename + ".patched.bak", "wb") as fh:
        fh.write(new_bin)

    print("Writing patch...")
    with open(filename, "wb") as fh:
        fh.write(new_bin)

    mode = os.stat(filename).st_mode
    os.chmod(filename, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print("Done!\n")
    subprocess.run(["ls", "-l", "/usr/bin/lpass*"], check=False)
    subprocess.run(["sha1sum", "/usr/bin/lpass*"], check=False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: patch.py LastPassBinaryPath")
        sys.exit(1)
    main(sys.argv[1])
