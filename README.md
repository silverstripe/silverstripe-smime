# Silverstripe S/MIME

This module enables Silverstripe CMS projects to use S/MIME when sending emails.
This is not a plug-and-play solution, as it depends on the provisioning and
configuration of a pair of keys for encrypting emails and optionally a pair of
keys for signing emails.

## Requirements

* Silverstripe framework ^4.9
* OpenSSL ^1.1.1
* Key pairs for encrypting and signing messages

## Installation

```
composer require silverstripe/smime dev-master
```
## Configuration

See the [configuration guide](/docs/en/configuration.md) for a full guide.

## Docs

See the [documentation](/docs/en/index.md).

## Development and contribution

If you would like to make contributions to the module please ensure you raise a
pull request and discuss with the module maintainers.

## Bugtracker

Bugs are tracked in the issues section of this repository. Before submitting an
issue please read over existing issues to ensure yours is unique.

If the issue does look like a new bug:

 - Create a new issue
 - Describe the steps required to reproduce your issue, and the expected
   outcome. Unit tests, screenshots and screencasts can help here.
 - Describe your environment as detailed as possible: Silverstripe CMS version,
   PHP version, Operating System, any installed Silverstripe CMS modules.

Please report security issues to security directly. Please don't
file security issues in the bugtracker.

## License

See [License](license.md)
