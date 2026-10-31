# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately**. Do not open a public
issue, pull request, or discussion for a suspected security problem.

Use GitHub's private vulnerability reporting for this repository:
https://github.com/XukuLLC/attesto/security/advisories/new

(From the repository's **Security** tab, choose **Report a vulnerability**.)

Reports are acknowledged as quickly as possible, and you will be kept informed
while the issue is investigated and a fix is prepared. Please allow a
reasonable period for a fix to ship before any public disclosure.

For coordinated disclosure and CVE assignment across the Erlang/Elixir
ecosystem, you may also contact the Erlang Ecosystem Foundation's CNA at
cna@erlef.org.

## Supported Versions

Security fixes are applied to the latest release on
[Hex](https://hex.pm/packages/attesto). Please upgrade to the latest version before
reporting an issue.

## Runtime floor

Every outbound TLS connection a host makes for this package (JWKS, OpenID
Federation entity statements, status lists, and the targets
`Attesto.OutboundTarget` pins) rides Erlang/OTP `ssl`. Two 2026 OTP advisories
let a TLS client skip server authentication: CVE-2026-55953 (TLS 1.2 and DTLS
client accepts an unoffered anonymous cipher suite; fixed in OTP 27.3.4.15,
28.5.0.4, 29.0.4) and CVE-2026-89422 (TLS 1.3 client skips server
authentication on an unsolicited `pre_shared_key` extension; fixed in OTP
27.3.4.18, 28.5.0.7, 29.1.1). Run this package on OTP 27.3.4.19, 28.5.0.8, or
29.1.2 or later, which also carry the October 2026 `ssl` and `inets` fixes.
OTP 26 has received no security patches since OTP 29.0 shipped.
