# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). You should receive a response within five working days.

## Handling inventory data

Inventories collected from live environments describe who can do what in your cloud. Treat them as sensitive:

1. Do not commit them. The `.gitignore` excludes common file names, but check before pushing.
2. Store them where only the security team can read them.
3. Delete them when the review is complete.

## Scope of the tool

This tool only reads configuration and produces recommendations. It does not apply changes. Review every plan before acting on it in production.
