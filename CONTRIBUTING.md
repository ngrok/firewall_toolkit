# Contributing

Hi there! We're thrilled that you'd like to contribute to Firewall Toolkit. Your help is essential for keeping it great.

Please note that this project adheres to the [Contributor Covenant Code of Conduct](/CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

If you have questions, or you'd like to check with us before embarking on a major development effort, please [open an issue](https://github.com/ngrok/firewall_toolkit/issues/new).

## How to contribute

This project uses the [GitHub Flow](https://guides.github.com/introduction/flow/). That means that the `master` branch is stable and new development is done in feature branches. Feature branches are merged into the `master` branch via a Pull Request.

0. Fork and clone the repository
0. Create a new branch: `git checkout -b my-branch-name`
0. Make your change, add tests, and make sure the tests still pass
0. Push to your fork and submit a pull request

We will handle updating the version, tagging the release, and releasing. Please don't bump the version or otherwise attempt to take on these administrative internal tasks as part of your pull request.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

* Use `make docker-linter` to ensure your code meets our style requirements.

- Write thorough tests. More than that tests should be very thorough and cover as many (edge) cases as possible. Write both unit and integration tests. Ensure that `make docker-ci` succeeds, including the linter and all tests.

- Bug fixes require specific tests covering the addressed behavior.

- Write or update documentation. If you have added a feature or changed an existing one, please make appropriate changes to the docs. Doc-only PRs are always welcome.

- Keep your change as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.

- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

## License note

We can only accept contributions that are compatible with the MIT license.

It's OK to depend on libraries licensed under either Apache 2.0 or MIT, but we cannot add dependencies that are licensed under GPL.

Any contributions you make must be under the MIT license.
