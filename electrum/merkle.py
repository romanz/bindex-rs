# Copyright (c) 2018, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

"""Merkle trees, branches, proofs and roots."""

from math import ceil, log
from typing import Optional, Callable, Tuple, Iterable, List

import hashlib

_sha256 = hashlib.sha256


def sha256(x):
    """Simple wrapper of hashlib sha256."""
    return _sha256(x).digest()


def double_sha256(x):
    """SHA-256 of SHA-256, as used extensively in bitcoin."""
    return sha256(sha256(x))


class Merkle:
    """Perform merkle tree calculations on binary hashes using a given hash
    function.

    If the hash count is not even, the final hash is repeated when
    calculating the next merkle layer up the tree.
    """

    def __init__(self, hash_func: Callable[[bytes], bytes] = double_sha256):
        self.hash_func = hash_func

    def branch_length(self, hash_count: int) -> int:
        """Return the length of a merkle branch given the number of hashes."""
        if not isinstance(hash_count, int):
            raise TypeError("hash_count must be an integer")
        if hash_count < 1:
            raise ValueError("hash_count must be at least 1")
        return ceil(log(hash_count, 2))

    def branch_and_root(
        self,
        hashes: Iterable[bytes],
        index: int,
        length: Optional[int] = None,
    ) -> Tuple[List[bytes], bytes]:
        """Return a (merkle branch, merkle_root) pair given hashes, and the
        index of one of those hashes.
        """
        hashes = list(hashes)
        if not isinstance(index, int):
            raise TypeError("index must be an integer")
        # This also asserts hashes is not empty
        if not 0 <= index < len(hashes):
            raise ValueError("index out of range")
        natural_length = self.branch_length(len(hashes))
        if length is None:
            length = natural_length
        else:
            if not isinstance(length, int):
                raise TypeError("length must be an integer")
            if length < natural_length:
                raise ValueError("length out of range")

        hash_func = self.hash_func
        branch = []
        for _ in range(length):
            if len(hashes) & 1:
                hashes.append(hashes[-1])
            branch.append(hashes[index ^ 1])
            index >>= 1
            hashes = [
                hash_func(hashes[n] + hashes[n + 1]) for n in range(0, len(hashes), 2)
            ]

        return branch, hashes[0]
