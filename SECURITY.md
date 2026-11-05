# Security policy

## Reporting a vulnerability

Please report security problems **privately**, through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Don't open a public issue or pull request for a
security problem.

You'll get an acknowledgement as soon as possible, and we'll agree on a fix and a
disclosure date with you. Credit is given in the advisory unless you'd rather not
be named.

**Never attach real data from a phone** (raw `dumpsys` output, case folders,
reports that aren't redacted). If a problem needs sample input, reproduce it with
a test fixture or synthetic values, or describe the shape of the data instead.

## What counts as a vulnerability here

appopsy reads personal data from a phone and promises not to change the device
or leak what it reads. In scope, for example:

- **Read-only guarantee:** any way to make appopsy run an adb command that isn't
  on its allowlist (`appopsy/adb.py`), or a process outside the two places allowed
  to start one (`adb.py`, `gitfiles.py`).
- **Redaction:** a redacted report (`--redact`) or a fixture made with
  `redact-fixture` that still contains a private app name, a device identifier,
  an exact time, or anything else its checks claim to remove.
- **Report injection:** device-supplied strings (package, job or alarm names)
  that can inject Markdown or HTML into a report, or make the HTML report run a
  script or load anything from the network.
- **File permissions:** case folders or reports written readable by other users.

Out of scope: what apps on your phone are doing (that's what appopsy reports on),
and inaccuracies in a finding's wording; please open a normal issue for those.

## Supported versions

Only the latest release, and the `main` branch, receive security fixes.

## If you're worried about stalkerware

If you think someone may be monitoring your phone, read the README's section
"If you're worried about stalkerware" before acting on any finding: removing
monitoring software can alert whoever installed it.
