# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The Changelog starts with v0.4.1, because we did not keep one before that,
and simply didn't have the time to go back and retroactively create one.

## [Unreleased]

- Fixed `linux.enumerate.system.network` to work with old and new style `ip`.
- Fixed `ChannelFile.recvinto` which will no longer raise `BlockingIOError` (#126, #131)
- Fixed sessions command with invalid session ID (#130)
- Fixed zsh shell prompt color syntax (#130)
- Added Pull Request template
- Added CONTRIBUTING.md

## [0.4.1] - 2021-06-14
### Added
- Differentiate prompt syntax for standard bash, zsh and sh (#126)
- Added `-c=never` to `ip` command in `linux.enumerate.system.network`
  (#126)
- Updated Dockerfile to properly build post-v0.4.0 releases (#125)
- Added check for `nologin` shell to stop pwncat from accidentally
  closing the session (#116)
- Resolved all flake8 errors (#123)
- Improved EOF handling for Linux file-writes (#117)
