#!/usr/bin/env python3
import threading
from typing import Optional, Union

import pwncat
import pwncat.channel
import pwncat.platform


class Session:
    """
    Combine a platform and a C2 channel to track an abstract session
    with a victim.
    """

    def __init__(
        self,
        platform: Union[str, pwncat.platform.Platform],
        channel: Optional[pwncat.channel.Channel] = None,
    ):

        # Allow creation of a session from a platform identifier
        # or from an already initialized platform object.
        if not isinstance(platform, pwncat.platform.Platform):
            self.platform: pwncat.platform.Platform = pwncat.platform.create(
                platform, channel=channel
            )
        else:
            self.platform: pwncat.platform.Platform = platform

        # Find the host hash identifying this unique victim
        host_hash = self.platform.get_host_hash()

        # Lookup the host hash in the database
        self.host: pwncat.db.Host = pwncat.db.get_session().query(
            pwncat.db.Host
        ).filter_by(hash=host_hash).first()

        # A lock used to ensure that multiple actions aren't performed
        # at the same time on one session. This is mainly implemented with
        # the intension of implementing multi-session capabilities into
        # pwncat in the future
        self.lock: threading.Lock = threading.Lock()

        # Bootstrap the new host object
        if self.host is None:
            self._bootstrap_new_host(host_hash)

    def _bootstrap_new_host(self, host_hash):
        """
        Utilize the enumerated host hash to build a new host object in the
        database. This tracks all data related to an individual host.
        """

    def __enter__(self) -> "Session":
        """ Acquire the session lock

        :return: the locked session object
        :rtype: pwncat.session.Session
        """

        self.lock.acquire()
        return self

    def __exit__(self):
        """ Release the session lock """

        self.lock.release()
