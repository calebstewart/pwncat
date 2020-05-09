#!/usr/bin/env python3
from typing import Type, List, Tuple

from pwncat.reader.base import Method, ReaderError, Technique
from pwncat.reader.cat import CatMethod


reader_methods = [CatMethod]


class Reader:
    """ Locate a privesc chain which ends with the given user. If `depth` is
    supplied, stop searching at `depth` techniques. If `depth` is not supplied
    or is negative, search until all techniques are exhausted or a chain is
    found. If `user` is not provided, depth is forced to `1`, and all methods
    to privesc to that user are returned. """

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        """ Create a new privesc finder """

        self.pty = pty

        self.methods: List[Method] = []
        for m in reader_methods:
            try:
                m.check(self.pty)
                self.methods.append(m(self.pty))
            except ReaderError:
                pass

    def search(self, filename: str) -> List[Technique]:
        """ Search for reader techniques."""

        techniques = []
        for method in self.methods:
            try:
                techniques.extend(method.enumerate(filename))
            except ReaderError:
                pass

        return techniques

    def read(self, filename: str,) -> str:
        """ Read a file using any known techniques """

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                found_techniques = method.enumerate(filename)
                for tech in found_techniques:

                    try:
                        filecontents = tech.method.execute(tech)
                        return filecontents
                    except ReaderError:
                        return None

                techniques.extend(found_techniques)
            except ReaderError:
                pass

        raise ReaderError(f"failed to read {filename}")
