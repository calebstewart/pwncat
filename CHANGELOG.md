# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The Changelog starts with v0.4.1, because we did not keep one before that,
and simply didn't have the time to go back and retroactively create one.

## [Unreleased]
### Fixed
- Pinned container base image to alpine 3.13.5 and installed to virtualenv ([#134](https://github.com/calebstewart/pwncat/issues/134))
- Fixed syntax for f-strings in escalation command
### Changed
- Changed session tracking so session IDs aren't reused
- Changed zsh prompt to match CWD of other shell prompts
- Improved exception handling in `Manager.interactive` ([#133](https://github.com/calebstewart/pwncat/issues/133))
- Added explicit permission checks when opening files

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
