# Security Health Check for Magento 2

![Security Health Check for Magento 2](docs/images/hero.webp)

A free security check for your Magento store. One page in the admin and a regular email tell you whether your
**Magento and PHP versions still get security fixes**, whether the **latest security patch** is installed, which
**Composer packages (extensions and libraries) have known vulnerabilities**, and which **admin and
configuration settings** leave the store open to attack, with a plain-English fix for each one.

> Tested on Magento Open Source 2.4.9 (PHP 8.3). Works the same with Hyvä and Luma: the module only runs in the
> admin, cron and the command line, so it adds nothing to your storefront.

[![CI](https://github.com/meetmage-extensions/magento2-module-security-health-check/actions/workflows/ci.yml/badge.svg)](https://github.com/meetmage-extensions/magento2-module-security-health-check/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

## Why

Most hacked Magento stores were running a version with a known, already fixed vulnerability, or an extension
with one. `composer audit` and Adobe's security bulletins can tell you, but only if someone remembers to look.
This module looks every day and tells you in the admin and by email.

## What it checks

### Magento and PHP versions
- **End of life:** is your Magento release line (for example 2.4.6) still supported, and until when?
  Data from [endoflife.date](https://endoflife.date/magento).
- **Latest security patch:** compares your version with the newest patch release of your line (for example
  2.4.8-p1 when 2.4.8-p5 is out).
- **Known vulnerabilities:** matches your exact version against the Magento security advisories in the
  [Packagist advisory database](https://packagist.org/packages/magento/community-edition/advisories).
- **PHP:** does your PHP version still get security fixes?

### Extensions and libraries
- Every installed Composer package is checked against the Packagist security advisory database (the same data as
  `composer audit`), with the CVE, severity and the `composer update` command to fix it.

### Admin access
- Two-factor authentication enabled (PCI DSS 8.4)
- Admin URL is not the default `/admin`
- No active admin user called `admin`, `administrator`, `root`, `test` …
- Admin account sharing off (PCI DSS 8.2.2)
- Account lockout after at most 10 failed logins (PCI DSS 8.3.4)
- Idle admin sessions end within 15 minutes (PCI DSS 8.2.8)
- CAPTCHA on the admin login, secret keys in admin URLs

### Store configuration
- Production mode, HTTPS on every store view, Content Security Policy module enabled, template hints off,
  cron running

## The report

- **System → Other Settings → Security Health Check**: a score out of 100, every issue with what was found and
  how to fix it, and a list of passed checks. The **Run check now** button checks again straight away.
- An **admin notice** appears while a critical or high issue is open.
- An **email report**: right away when a new medium, high or critical issue appears, and weekly or daily while
  issues stay open (your choice).
- **Command line** for deployment pipelines:

```bash
bin/magento meetmage:security:check            # print the issues
bin/magento meetmage:security:check --all      # include passed checks
bin/magento meetmage:security:check --email    # also email the report
bin/magento meetmage:security:check --fail-on=high   # exit code 1 if a high or critical issue is open
```

## Privacy

The check reads public data from Packagist, endoflife.date and the Magento release feed (by default the public
[Mage-OS mirror](https://mirror.mage-os.org/)). It sends **package names only**: your installed versions,
configuration and store data never leave your server, and the comparison happens locally. Turn off **Look Up
Public Security Data** to run only the configuration checks, with no outgoing requests.

## Compatibility

| | Supported |
|---|---|
| Magento Open Source / Adobe Commerce | 2.4.6 – 2.4.9 |
| PHP | 8.1 – 8.5 |
| Storefront | Any (admin-only module): Luma, Hyvä, headless |

## Installation

```bash
composer require meetmage/module-security-health-check
bin/magento module:enable MeetMage_SecurityHealthCheck
bin/magento setup:upgrade
bin/magento cache:flush
```

Then open **System → Other Settings → Security Health Check** and click **Run check now**. After that, cron runs
the check every day at 04:23 server time.

## Configuration

**Stores → Configuration → MeetMage → Security Health Check**

| Setting | Default | Description |
|---|---|---|
| Run Daily Check | Yes | Daily check by cron |
| Look Up Public Security Data | Yes | Version and vulnerability checks (see Privacy) |
| Magento Release Feed | Mage-OS mirror | Composer metadata listing Magento releases (https only) |
| Ignored Checks | – | Finding codes to hide, one per line; end with `*` for a group, e.g. `packages.advisories.vendor/*` |
| Send Email Report / When to Send / Send To / Sender / Template | No / Weekly / – / General / default | Report emails |

## Adding your own checks

Implement `MeetMage\SecurityHealthCheck\Model\Check\CheckInterface` (return a list of `Finding` objects) and add
it to the `checks` argument of `MeetMage\SecurityHealthCheck\Model\Scanner` in your module's `di.xml`.

## Limits

- Public advisory data is only as complete as its sources: Adobe security bulletins sometimes reach the Packagist
  database late, which is why the latest-patch check is separate and does not depend on it.
- Extensions installed in `app/code` (not through Composer) have no version data and are not checked for
  advisories.
- Server-level settings (firewall, file permissions, web server headers) are outside Magento and not checked.
- A health score is a guide, not a certification. For PCI DSS, see also
  [Payment Script Guard](https://github.com/meetmage-extensions/magento2-module-payment-script-guard) for
  requirements 6.4.3 and 11.6.1.

## Support

Free and open source (MIT). Bugs and ideas:
[GitHub issues](https://github.com/meetmage-extensions/magento2-module-security-health-check/issues).
Need help fixing what the report finds, or a Magento upgrade? [Meet Shekhat](https://meetshekhat.com),
freelance Magento developer.
