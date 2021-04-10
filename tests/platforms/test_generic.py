#!/usr/bin/env python3
import os
import base64


def test_file_read_printable(session, tmp_path):
    """ Test abstracted linux path interaction """

    # Printable data to read from a file
    expected_contents = base64.b64encode(os.urandom(4096)).decode("utf-8")

    # Write to a temporary file
    with (tmp_path / "test").open("w") as filp:
        filp.write(expected_contents)

    # Attempt to read through linux session
    with (session.platform.Path(str(tmp_path)) / "test").open("r") as filp:
        contents = filp.read()

    # Ensure match
    assert contents == expected_contents


def test_file_read_binary(session, tmp_path):
    """ Test abstract linux path read for binary data """

    # Generate unique random data
    expected_contents = os.urandom(8192)

    with (tmp_path / "test").open("wb") as filp:
        filp.write(expected_contents)

    with (session.platform.Path(str(tmp_path)) / "test").open("rb") as filp:
        contents = filp.read()

    assert contents == expected_contents


def test_file_write_printable(session, tmp_path):
    """ Test abstract file-write w/ printable data """

    # Printable data to write to a file
    expected_contents = base64.b64encode(os.urandom(4096)).decode("utf-8")

    # Write to a temporary file
    with (session.platform.Path(str(tmp_path)) / "test").open("w") as filp:
        filp.write(expected_contents)

    # Attempt to read through linux session
    with (tmp_path / "test").open("r") as filp:
        contents = filp.read()

    # Ensure match
    assert contents == expected_contents


def test_file_write_binary(session, tmp_path):
    """ Test abstract file-write w/ binary data """

    # data to write to a file
    expected_contents = os.urandom(8192)

    # Write to a temporary file
    with (session.platform.Path(str(tmp_path)) / "test").open("wb") as filp:
        filp.write(expected_contents)

    # Attempt to read through linux session
    with (tmp_path / "test").open("rb") as filp:
        contents = filp.read()

    # Ensure match
    assert contents == expected_contents


def test_file_stat(session, tmp_path):
    """ Test various stat routines """

    dir_path = tmp_path / "directory"
    dir_path.mkdir(exist_ok=True, parents=True)

    file_path = dir_path / "file"
    file_path.touch()

    symlink_path = dir_path / "symlink"
    symlink_path.symlink_to(file_path)

    # NOTE - this doesn't work on real python, and I'm not sure why... :sob:
    # link_path = dir_path / "link"
    # link_path.link_to(file_path)

    dir_path = session.platform.Path(str(dir_path))
    file_path = session.platform.Path(str(file_path))

    # Ensure appropriate properties
    assert dir_path.is_dir()
    assert not dir_path.is_file()
    assert not dir_path.is_mount()
    assert not dir_path.is_symlink()
    assert not dir_path.is_socket()
    assert not dir_path.is_fifo()
    assert not dir_path.is_block_device()
    assert not dir_path.is_char_device()

    # Ensure appropriate file properties
    assert file_path.is_file()
    assert not file_path.is_dir()
    assert not file_path.is_mount()
    assert not file_path.is_symlink()
    assert not file_path.is_socket()
    assert not file_path.is_fifo()
    assert not file_path.is_block_device()
    assert not file_path.is_char_device()

    # Ensure symlink properties are correct
    assert symlink_path.is_file()
    assert not symlink_path.is_dir()
    assert not symlink_path.is_mount()
    assert symlink_path.is_symlink()
    assert not symlink_path.is_socket()
    assert not symlink_path.is_fifo()
    assert not symlink_path.is_block_device()
    assert not symlink_path.is_char_device()

    # Ensure link properties are correct
    # See above note on why this is commented...
    # assert link_path.is_file()
    # assert not link_path.is_dir()
    # assert not link_path.is_mount()
    # assert not link_path.is_symlink()
    # assert not link_path.is_socket()
    # assert not link_path.is_fifo()
    # assert not link_path.is_block_device()
    # assert not link_path.is_char_device()

    # Ensure iterdir works
    assert str(file_path) in [str(item) for item in dir_path.iterdir()]

    # link_path.unlink()
    symlink_path.unlink()
    assert not (dir_path / "symlink").exists()

    file_path.unlink()
    assert not (dir_path / "file").exists()

    dir_path.rmdir()
    assert not (session.platform.Path(tmp_path) / "directory").exists()

    # Ensure mount point is correct
    assert session.platform.Path("/").is_mount()


def test_file_creation(session, tmp_path):
    """ Test various file creation methods """

    remote_path = session.platform.Path(tmp_path)

    # Create a directory
    (remote_path / "directory").mkdir()
    assert (remote_path / "directory").is_dir()

    # Remove directory
    (remote_path / "directory").rmdir()
    assert not (remote_path / "directory").is_dir()

    # Touch a file
    (remote_path / "file").touch()
    assert (remote_path / "file").is_file()

    # Delete file
    (remote_path / "file").unlink()
    assert not (remote_path / "file").is_file()
