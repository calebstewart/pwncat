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
