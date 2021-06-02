Download
========

The ``download`` command provides an easy way to exfiltrate files from the victim. All file transfers are made over
the same connection as your shell, and there are no HTTP or raw socket ports needed to make these transfers.
File transfers are accomplished by utilizing the ``gtfobins`` framework to locate file readers on the victim host and
write the contents back over the pipe. In some cases, this includes and requires encoding the data on the victim end
and automatically decoding on the attacking host.

The ``download`` command has a simply syntax which specifies the source and destination files only. The source file is
a file on the remote host, which will be tab-completed at the pwncat prompt. The destination is a local file path
on your local host which will be created (or overwritten if existing) with the content of the remote file.

.. code-block:: bash
    :caption: Downloading the contents of /etc/hosts to a local file

    download /etc/hosts ./victim-hosts

