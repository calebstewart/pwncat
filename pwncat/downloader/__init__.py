#!/usr/bin/env python3

from pwncat.downloader.base import Downloader, DownloadError
from pwncat.downloader.nc import NetcatDownloader
from pwncat.downloader.curl import CurlDownloader
from pwncat.downloader.shell import ShellDownloader

all_downloaders = [NetcatDownloader, CurlDownloader, ShellDownloader]
downloaders = [NetcatDownloader, CurlDownloader]
fallback = ShellDownloader


def find(pty: "pwncat.pty.PtyHandler", hint: str = None) -> Downloader:
    """ Locate an applicable downloader """

    if hint is not None:
        """ Try to return the requested downloader """
        for d in all_downloaders:
            if d.NAME != hint:
                continue
            d.check(pty)
            return d

    for d in downloaders:
        try:
            d.check(pty)
            return d
        except DownloadError:
            continue

    raise DownloadError("no acceptable downloaders found")
