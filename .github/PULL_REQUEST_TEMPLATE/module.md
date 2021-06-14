---
name: New Module
about: Merge changes to add a new pwncat module
title: "[NEW-MODULE] "
labels:
    - enhancement
    - new-module
assignees: ""
---

**Module Goals**
*Describe in detail what your module is for, and how it accomplishes
the task from a technical standpoint.*

**Platform Restrictions:**
*Linux/Windows/None/etc*

**Fully Qualified Name:**
*enumerate.something.cool*

**Environment Restrictions:**
*Anything that is required in the environment for the module to function*

**Artifacts Generated:**
*List any artifacts that this module may generate on the victim*

**Tested Targets**
*Where have you tested this module? What have you done to test against
verious distributions/systems and ensure wide-coverage? Does the module
behave properly (e.g. raise appropriate exception, fail silently) if the
environment doesn't match?*

**note - remove following before post submitting, please :)**

The following should be completed before opening a pull request:

- `isort` any modified files.
- `black` format any modified files
- Correct any outstanding `flake8` errors.
- Note any `noqa:` comments need in your PR to appease flake.
