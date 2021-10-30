# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The Changelog starts with v0.4.1, because we did not keep one before that,
and simply didn't have the time to go back and retroactively create one.

## [Unreleased]

### Fixed
- Added new `peas` module which run [PEASS-ng](https://github.com/carlospolop/PEASS-ng) scripts and binaries
- Fixed mktemp function in the both platforms
- Fixed linux state variable (`time of file birth`) due to unknowns errors

## [Unreleased]

### Fixed
- Possible exception due to _pre-registering_ of `session` with `manager`
- Covered edge case in sudo rule parsing for wildcards ([#183](https://github.com/calebstewart/pwncat/issue/183))
- Added fallthrough cases for PTY methods in case of misbehaving binaries (looking at you: `screen`)
- Fixed handling of `socket.getpeername` when `Socket` channel uses IPv6 ([#159](https://github.com/calebstewart/pwncat/issues/159)).
- Fixed verbose logging handler to be __unique__ for every `channel`
- Fixed docstrings in `Command` modules
- Changed docker base image to `python3.9-alpine` to fix python version issues.
- Added logic for calling correct paramiko method when reloading an encrypted SSH privat ekey ([#185](https://github.com/calebstewart/pwncat/issues/185)).
- Forced `Stream.RAW` for all GTFOBins interaction ([#195](https://github.com/calebstewart/pwncat/issues/195)).
- Added custom `which` implementation for linux when `which` is not available ([#193](https://github.com/calebstewart/pwncat/issues/193)).
- Correctly handle `--listen` argument ([#201](https://github.com/calebstewart/pwncat/issues/201))
### Added
- Added alternatives to `bash` to be used during _shell upgrade_ for a _better shell_
- Added a warning message when a `KeyboardInterrupt` is caught
- Added `--verbose/-V` for argument parser
- Added `OSError` for `bind` protocol to show appropriate error messages
- Contributing guidelines for GitHub maintainers
- Installation instructions for BlackArch
### Changed
- Changed some 'red' warning message color to 'yellow'
- Leak private keys for all users w/ file-read ability as UID=0 ([#181](https://github.com/calebstewart/pwncat/issues/181))
- Raise `PermissionError` when underlying processes terminate unsuccessfully for `LinuxReader` and `LinuxWriter`

## [0.4.3] - 2021-06-18
Patch fix release. Major fixes are the correction of file IO for LinuxWriters and
improved stability with better exception handling.

### Fixed
- Pinned container base image to alpine 3.13.5 and installed to virtualenv ([#134](https://github.com/calebstewart/pwncat/issues/134))
- Fixed syntax for f-strings in escalation command
- Re-added `readline` import for windows platform after being accidentally removed
- Corrected processing of password in connection string
### Changed
- Changed session tracking so session IDs aren't reused
- Changed zsh prompt to match CWD of other shell prompts
- Improved exception handling throughout framework ([#133](https://github.com/calebstewart/pwncat/issues/133))
- Added explicit permission checks when opening files
- Changed LinuxWriter close routine again to account for needed EOF signals ([#140](https://github.com/calebstewart/pwncat/issues/140))
### Added
- Added better file io test cases

## [0.4.2] - 2021-06-15
Quick patch release due to corrected bug in `ChannelFile` which caused command
output to be empty in some situations.

### Fixed
- Fixed `linux.enumerate.system.network` to work with old and new style `ip`.
- Fixed `ChannelFile.recvinto` which will no longer raise `BlockingIOError` ([#126](https://github.com/calebstewart/pwncat/issues/126), [#131](https://github.com/calebstewart/pwncat/issues/131))
- Fixed sessions command with invalid session ID ([#130](https://github.com/calebstewart/pwncat/issues/130))
- Fixed zsh shell prompt color syntax ([#130](https://github.com/calebstewart/pwncat/issues/130))
### Added
- Added Pull Request template
- Added CONTRIBUTING.md
- Added `--version` option to entrypoint to retrieve pwncat version
- Added `latest` tag to documented install command to prevent dev installs

## [0.4.1] - 2021-06-14
### Added
- Differentiate prompt syntax for standard bash, zsh and sh ([#126](https://github.com/calebstewart/pwncat/issues/126))
- Added `-c=never` to `ip` command in `linux.enumerate.system.network`
  ([#126](https://github.com/calebstewart/pwncat/issues/126))
- Updated Dockerfile to properly build post-v0.4.0 releases ([#125](https://github.com/calebstewart/pwncat/issues/125))
- Added check for `nologin` shell to stop pwncat from accidentally
  closing the session ([#116](https://github.com/calebstewart/pwncat/issues/116))
- Resolved all flake8 errors ([#123](https://github.com/calebstewart/pwncat/issues/123))
- Improved EOF handling for Linux file-writes ([#117](https://github.com/calebstewart/pwncat/issues/117))
