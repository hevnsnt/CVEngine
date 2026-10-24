# Contributing

Contributions are welcome: bug fixes, features, and documentation.

## Reporting a bug

Open an issue and describe what happened, with the exact error message and the steps to reproduce it. Search the existing issues first to avoid duplicates. Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Feature requests

Open an issue that explains the problem and the use case. Context helps us judge whether it fits the project.

## Pull requests

Ask in an issue before starting a large change such as a new feature or a refactor, so the work is not wasted.

1. Fork the repository and clone your fork.
2. Create a branch for your change.
3. Copy `.env.example` to `.env`, start the dev stack with `docker compose -f docker-compose.dev.yml up -d`, and run the tests with `docker compose -f docker-compose.dev.yml exec celery python3 manage.py test tests`.
4. Open a pull request that says what changed and why.

By contributing you agree that your work is released under the [GPL-3.0](../LICENSE). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
