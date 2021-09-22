# Contributing

If you have an idea for a new feature or just want to help out with a bug
fix, please refer to this guide and follow the rules before submitting a
pull request.

## Submitting Issues

If you aren't a programmer or don't have the time to contribute code to the
project, we would still appreciate bug reports and feature requests. Please
use the appropriate issue type in the GitHub issue system to report either
bugs or feature requests.

When reporting bugs, ensure you include the current version pwncat you have
installed, what type of target/victim you are using, what payload you used
on the target to gain a shell, any relevant tracebacks, and of course
screenshots if they add context to your problem. In general, the more
information we have, the more chance there is we can fix the problem.

For feature requests, please be very specific on what you would like pwncat
to do. We can't read your mind, and English isn't perfect. If you are
interested in or willing to help implement your new feature, please explicitly
let us know. This will help in prioritizing the issue.

## Submitting Pull Requests

When submitting a pull request, ensure you have read through and comply with
these contributing rules. The pull request template should guide you through
the things that need done before merging code.

For help with running pre-merge tools, see the styling and formatting section
below. For running pytest test cases, see the testing section.

Before submitting your changes in a pull request, please add a brief one-line
summary to the `CHANGELOG.md` file under the `[Unreleased]` heading. This makes
releases more straightforward and bug fixes and features are added along the way.
For information on the format of the changelog, see
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

If you are submitting a bug fix, annotate this with `Fixes #XXX` replacing the
`XXX` with the issue number. This ensures that the issue will be closed once
the bug fix is merged. If your bug fix does not **completely** fix the issue,
do not use the `Fixes` keyword. Instead, mention the issue by number in your
pull request to ensure the link between the issue and pull request is clear.

## Versioning

pwncat follows Semantic Versioning. You can learn about the basics of semver
[here](https://semver.org). pwncat does not currently have any release
schedule, but in general the following rules apply:

- `PATCH` fixes are released whenever there is either significant aggregate of
  bug fixes or when a significantly agregious bug is fixed. The decision for
  what "significant" means will be decided by a project owner.
- `MINOR` releases are for added functionality. The pwncat API is relatively
  stable, but still has not attained `v1.0.0` status, and therefore minor
  releases could make breaking API changes. However, a concerted effort
  should be made to make all changes backwards compatible.

As mentioned above, pwncat has not reached `v1.0.0` yet. As such, I don't have
rules yet for `MAJOR` version bumps. I will update this file as the situation
develops.

## Making Changes

In general, when contributing to a project on GitHub, you should work from a
branch. This helps organize your changes within the project. There are two
main branches which pwncat uses to organize contributions: `master` and the
next release branch (named like `release-vX.Y.Z`).

- Any bug fixes which do not add new features should be made targeting `master`.
- Any new features should be made targeting the latest `release-vX.Y.Z`.

When forking the repository to make contributions, you can work directly out
of your fork's `master` or `release` branches or fork them. When creating a
pull request, you must target the appropriate branch based on the intent of
your work.

Pull requests targeting the wrong branch will be retargeted, which could
cause issues while merging.

## Styling and Format

The majority of pwncat is written in Python. We use `python-black` to format
code in a consistent and readable manner. We recommend you install a Black
plugin for your editor or IDE to ensure all code is formatted prior to
opening a pull request.

Beyond Black, you should also run `isort` and `flake8` within your branch
prior to opening a pull request. `isort` will sort your imports to ensure
they are easy to read. `flake8` will notify you of some common Python
errors. pwncat has `flake8` and `isort` configurations, so the process is
as simple as running the associated tool.

Prior to creating a pull request, please run the following from the repository
root to ensure formatting is in order:

```sh
# Automatically fixes imports
isort ./pwncat
# Automatically fixes formatting
black ./pwncat
# Warns of errors or other syntax problems
flake8
```

## Testing Your Changes

Testing pwncat is difficult. There are some unit tests implemented in `tests/`.
These tests can be executed with `pytest`, but you must provide suitable targets
for the testing framework. The `run-tests.sh` script uses `podman` to start two
containers to act as targets, and then runs all tests. One container is a Ubuntu
machine with a bind shell and the other is a CentOS container with a bind shell.

If you are creating Windows features, you can run the Windows tests as well by
manually providing a Windows bind shell target:

```sh
WINDOWS_HOST=10.10.10.10 WINDOWS_BIND_PORT=4444 ./run-tests.sh
```

The included unit tests are not great. They do not have a lot of coverage, but
they at least ensure that the basic automated functionality of pwncat is not
broken across some common target types.

## Maintainer Responsibilities and Expectations

The primary maintainer or repository owner will be Caleb Stewart (`calebstewart`)
until otherwised announced or changed in the future. Other users may be invited
as Co-Maintainers in the future to assist in the daily maintenance, issue review
and pull request review processes with the project. The follow section describes
the expectations of Co-Maintainers within the project and their conduct.

This is a community project supported by open source software and as such, there
are no requirements for participation in development or review. At any time, a
Co-Maintainer can request to leave the project with no hard feelings. Co-Maintainers
will be invited based on consistent interaction with the project including issues,
pull requests and discussions. Additionally, the quality of interactions with
respect to the above contribution guidelines will also be taken into account.

We understand this is a part time involvement. There is no expectation or
agreement between you and this project which requires your participation.
pwncat is an open source project, and participation is obviously voluntary.
If at any time, you feel overwhelmed or simply lack the free time to
support the project, you have no responsiblity to contribute simply by
accepting the role of a co-maintainer.

Just as Co-Maintainer participation is not bound by any formal requirements or
agreement, the status of Co-Maintainer can be revoked at any time by the primary
maintainer normally based on the following criteria:

- Active particpation in issues and pull requests.
- Professionalism in correspondence with contributors.
- Adherence to the above contribution guidelines.
- Other factors determined by the primary maintainer which negatively impact
  the pwncat community or code base.

In addition to the above guidelines for issue and pull request submission,
Co-Maintainers are expected to participate in third-part issues and pull
requests. This is the main goal of inviting Co-Maintainers. Your assistance
in maintaining the project and producing a helpful tool for the community
is greatly appreciated. :)

As a Co-Maintainer, you **do not** have permission to merge pull requests which
implement new features into any branch. Co-Maintainers are expected to assist in
the review and application of bug fixes and resolution of issues. When creating new
features, the primary maintainer is responsible for approving and merging changes.
Merging changes into `release` branches is strictly a role of the primary maintainer.

Further, Co-Maintainers should not cut new releases of any kind. Cutting minor and
major releases is the sole responsibility of the primary maintainer. If a
Co-Maintainer believes a new minor release is needed in order to implement important
bug fixes, a pull request can be opened bumping the version number **separately
from any other changes** explaining the need for a new version release and request
a review from the primary maintainer. At which point, the primary maintainer will
review and cut a release if appropriate.

In contrast, Co-Maintainers are expected to do the following as your personal
life permits:

- Uphold the above contributing guidelines at all times. This includes when
  opening personal issues and pull requests as well as helping to *instruct*
  users when the guidelines are not being followed. This project should always
  foster Open Source contribution and learning, and therefore this instruction
  to third-party contributors should always be polite and constructive.
- Participate as a primary voice in issues and pull requests. In no way are
  you required to particpate in every issue or pull request, however as a
  Co-Maintainer, you are expected to have a higher level of knowledge,
  participation and/or professionalism when interacting with third-parties.
- Merge bug-fixes which adhere to the above contribution guidelines and which
  have been thoroughly tested. Co-Maintainers act as reviewers for bug-fix pull
  requests and have permission to merge those changes into the `master` branch.

If you have an interest in becoming a Co-Maintainer, would like to be removed
as a Co-Maintainer or have a general question about these guidelines, feel free
to reach out to the primary maintainer. At the time of writing, you can reach
out in the following ways:

- Open a discussion in the `Discussions` tab of GitHub.
- Send an E-mail directly to `Caleb Stewart <caleb.stewart94@gmail.com>`.
