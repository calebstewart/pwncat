#!/usr/bin/env python3
from typing import Type

from pwncat.downloader.base import Downloader, DownloadError
from pwncat.downloader.nc import NetcatDownloader
from pwncat.downloader.curl import CurlDownloader
from pwncat.downloader.shell import ShellDownloader

all_downloaders = [NetcatDownloader, CurlDownloader, ShellDownloader]
downloaders = [NetcatDownloader, CurlDownloader]
fallback = ShellDownloader


def find(pty: "pwncat.pty.PtyHandler", hint: str = None) -> Type[Downloader]:
    """ Locate an applicable downloader """

    if hint is not None:
        """ Try to return the requested downloader """
        for d in all_downloaders:
            if d.NAME != hint:
                continue
            d.check(pty)
            return d
        else:
            raise DownloadError(f"{hint}: no such downloader")

    for d in downloaders:
        try:
            d.check(pty)
            return d
        except DownloadError as e:
            continue

    try:
        fallback.check(pty)
        return fallback
    except:
        raise DownloadError("no acceptable downloaders found")
