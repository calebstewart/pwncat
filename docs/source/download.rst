File Download
=============

File download is performed in a similar fashion to file upload. The interface is largely the same
with the parameter order swapped ("source" is a remote file while "destination" is a local file).
This command provides the same local and remote tab-completion and progress bar as with the upload
command.

.. code-block:: bash

    (local) pwncat$ download --help
    usage: download [-h] source destination

    Download a file from the remote host to the local host

    positional arguments:
      source
      destination

    optional arguments:
      -h, --help   show this help message and exit

