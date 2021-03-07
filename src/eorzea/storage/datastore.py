#!/usr/bin/env python3
# vim: ts=4 expandtab

"""
A data store of names of people who can save Eorzea.

This base class provides in memory storage, and has two abstract functions
of `_write_append` for incremental updates and `_write_list` for full
rebuilds of a backing store, of which one of which SHOULD have a complete
implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, List, Optional, Type
from random import SystemRandom

from .record import Record


RaiseType = Optional[Type[Exception]]


class DataStore(ABC):
    """
    A data store of names of people who can save Eorzea.

    This base class provides in memory storage, and has two abstract functions
    of `_write_append` for incremental updates and `_write_list` for full
    rebuilds of a backing store, of which one of which SHOULD have a complete
    implementation.
    """

    known: Optional[Dict[str, Record]]
    rand: SystemRandom = SystemRandom()

    def __init__(self: DataStore, values: Optional[List[Record]] = None):
        """Sets up the data store, with the initial set of data that was
        loaded out of the data store"""
        super().__init__()

        # store the initial set of values.
        self.known = {r.name: r for r in values} if values else None
        self.rand = SystemRandom()

    def add(self: DataStore, value: str, added_by: str, added_from: str) -> bool:
        """Adds a value to the DataStore.

        If this value is already in the store, this function is a no-op that
        will always return true.

        Otherwise, this function will return true if the data is successfully
        written to both the in-memory storage and to the backing store."""
        if self.known and value in self.known:
            return True

        record = Record(value, added_by, added_from)

        # Function succeeds iff the backing store if updated,
        # _or_ if this DataStore does not support incremental
        # updates.
        if self._write_append(record) in [False]:
            return False

        if self.known:
            self.known[record.name] = record

        return True

    def random(self: DataStore) -> Record:
        """Selects a random element from this store."""

        if not self.known:
            raise Exception("Empty storage")

        options = [v for v in self.known.values() if v.approved]

        return self.rand.sample(options, 1)[0]

    def moderation_queue(self: DataStore) -> Generator[Record, None, None]:
        """Gets a list of values that are not moderated"""

        if not self.known:
            return

        yield from filter(lambda v: not v.approved, self.known.values())

    @abstractmethod
    def approve(self: DataStore, name: str) -> None:
        """Approves a Record with the given name"""

    @abstractmethod
    def _write_append(self: DataStore, record: Record) -> Optional[bool]:
        """Append a value to the underlying data store this type implements.

        This function may be a no-op method, in which case it MUST return None.
        Otherwise, it should return if the write succeeded.

        Values passed to this function SHOULD NOT exist in the store already,
        so the implement does not need to consider de-duplication.
        """

    @abstractmethod
    def _write_list(self: DataStore, record: List[Record]) -> Optional[bool]:
        """Writes an entire list to the backing store, replacing any existing
        list.

        This function may be a no-op, in which case it must always return None.
        Otherwise, it should return whether or not the operation succeeded."""

    def __len__(self: DataStore) -> int:
        if not self.known:
            raise Exception("Empty storage")

        return len(self.known)

    def __enter__(self: DataStore) -> DataStore:
        return self

    def __exit__(
        self: DataStore, exception_type: RaiseType, message: Any, traceback: Any
    ) -> Optional[bool]:
        if self.known:
            if self._write_list(list(self.known.values())) in [False]:
                raise Exception("Error writing list to DataStore")

        return exception_type is None
