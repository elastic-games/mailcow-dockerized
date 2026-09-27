"""Descriptor-relative no-symlink path boundary for native maildir transactions.

An eventual mover must keep these directory descriptors open and use dir_fd
operations/renameat2(RENAME_NOREPLACE), not convert them back to pathname strings.
Actual journalled store+index move/recovery remains a separate acceptance gate.
"""
from contextlib import contextmanager
import os
from pathlib import Path

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@contextmanager
def rooted_directory(root: Path, components: tuple[str, ...]):
    handles = []
    try:
        if any(not isinstance(part, str) or not part or part in ('.','..') or '/' in part or '\\' in part or '\x00' in part for part in components):
            raise ValueError('Invalid root-bound directory component')
        handles.append(os.open(root, DIRECTORY_FLAGS))
        for part in components:
            handles.append(os.open(part, DIRECTORY_FLAGS, dir_fd=handles[-1]))
        yield handles[-1]
    finally:
        for handle in reversed(handles): os.close(handle)
