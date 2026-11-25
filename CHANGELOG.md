# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-25

### Added
- Daily security health check with a 0-100 score, admin report page (System > Other Settings > Security Health
  Check), "Run check now" button and an admin notice for critical and high issues.
- Magento version checks: end of life (endoflife.date), latest security patch of the release line (Magento
  release feed) and known vulnerabilities (Packagist advisories). Advisories published before a release line
  came out are ignored for that line, because they sometimes list its unreleased version.
- PHP end-of-life check.
- Composer package check against the Packagist security advisory database (package names only are sent).
- Hardening checks: production mode, admin URL, two-factor authentication, HTTPS, common admin usernames, admin
  account sharing, lockout, session lifetime, admin CAPTCHA, secret keys in URLs, Content Security Policy,
  template hints and cron.
- Email report (on new issues, weekly or daily), ignore list, and `bin/magento meetmage:security:check` with
  `--all`, `--email` and `--fail-on`.
