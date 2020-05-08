#!/usr/bin/env python3

from typing import Type, List

from pwncat.downloader.base import Downloader, DownloadError
from pwncat.downloader.nc import NetcatDownloader
from pwncat.downloader.curl import CurlDownloader
from pwncat.downloader.shell import ShellDownloader
from pwncat.downloader.bashtcp import BashTCPDownloader

all_downloaders = [
    NetcatDownloader,
    CurlDownloader,
    ShellDownloader,
    BashTCPDownloader,
]
downloaders = [NetcatDownloader, CurlDownloader]
fallback = ShellDownloader


def get_names() -> List[str]:
    """ get the names of all downloaders """
    return [d.NAME for d in all_downloaders]


def find(pty: "pwncat.pty.PtyHandler", hint: str = None) -> Type[Downloader]:
    """ Locate an applicable downloader """

    if hint is not None:
        # Try to return the requested downloader
        for d in all_downloaders:
            if d.NAME != hint:
                continue
            d.check(pty)
            return d

        raise DownloadError(f"{hint}: no such downloader")

    for d in downloaders:
        try:
            d.check(pty)
            return d
        except DownloadError:
            continue

    try:
        fallback.check(pty)
        return fallback
    except:
        raise DownloadError("no acceptable downloaders found")
