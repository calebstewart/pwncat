#!/usr/bin/env python3
from typing import Type, List

from pwncat.uploader.base import Uploader, UploadError
from pwncat.uploader.nc import NetcatUploader
from pwncat.uploader.curl import CurlUploader
from pwncat.uploader.shell import ShellUploader

all_uploaders = [NetcatUploader, CurlUploader, ShellUploader]
uploaders = [NetcatUploader, CurlUploader]
fallback = ShellUploader


def get_names() -> List[str]:
    """ Return the names of all uploaders """
    return [u.NAME for u in all_uploaders]


def find(pty: "pwncat.pty.PtyHandler", hint: str = None) -> Type[Uploader]:
    """ Locate an applicable uploader """

    if hint is not None:
        # Try to return the requested uploader
        for d in all_uploaders:
            if d.NAME != hint:
                continue
            d.check(pty)
            return d

        raise UploadError(f"{hint}: no such uploader")

    for d in uploaders:
        try:
            d.check(pty)
            return d
        except UploadError:
            continue

    try:
        fallback.check(pty)
        return fallback
    except:
        raise UploadError("no acceptable uploaders found")
