# Contributing to apishield

Thanks for your interest in contributing! apishield — full-stack team task manager (MERN): JWT auth, role-based access, projects, kanban boards with drag-and-drop, tasks, comments.

Please read this guide before opening a pull request.

## How to contribute

1. Open an issue first for bugs, features, or questions, so the work can be
   discussed before you start.
2. Fork the repository and create a branch from `main`, named after the
   change (`feat/short-name`, `fix/short-name`, or `docs/short-name`).
3. Keep changes focused: one issue per pull request.
4. Follow the existing code style and add or update tests for behaviour
   changes.
5. Run the test suite locally before submitting.
6. Open a pull request against `main` using the pull request template and
   describe what changed, why, and how it was tested.

## Getting started

```bash
git clone https://github.com/<your-username>/apishield.git
cd apishield
```

## Setup

This project has separate `server/` and `client/` packages. Install both:

```bash
npm --prefix server install
npm --prefix client install
```

## Tests

Run the full test suite from the repository root:

```bash
python -m pytest -q
```

## Style

- Prefer small, readable functions and clear names.
- Do not commit secrets, credentials, tokens, or personal data.
- Update documentation (README / docs) when behaviour changes.

## Review

Maintainers may request changes. Please respond to review comments and keep
the pull request up to date with `main`.

Thank you for helping make apishield better!
