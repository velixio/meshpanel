# Security policy

meshpanel controls who joins your network, so we take reports seriously.

## Reporting

Please **do not open a public issue** for vulnerabilities. Use GitHub's
private vulnerability reporting ("Report a vulnerability" on the Security
tab). Include steps to reproduce and the version (`meshpanel version`).

We aim to acknowledge reports within 3 working days and to ship a fix for
confirmed high-severity issues within 14 days.

## Scope

In scope: authentication, 2FA, sessions, CSRF, the permission and ownership
model, the registration/approval flow, the Telegram bot, config/policy
editing, and anything that lets one panel user affect devices they can't see.

Out of scope: vulnerabilities in headscale itself (report those upstream),
and deployments that expose port 8030 directly to the internet without a
TLS proxy against the documentation.
