# Contributing

Bug reports, ideas and pull requests are welcome. LabLantern is a hobby project, so answers may take a while.

## Before you post

Logs and screenshots often show your network. Replace IP addresses, host names, domains and anything that looks like
a token before you paste them. Security problems go through private reporting, see [SECURITY.md](SECURITY.md).

## Development

See [README.md](README.md#development) for the server and web UI. Agent changes are tested in the build image, so
you do not need Go installed:

```bash
cd deploy && docker compose build agent-build   # runs go vet and go test
```

A pull request should keep all three suites green (`pytest`, `npm test`, `go test`) and add a test for the change.
Most code comments are in German; English comments in new code are fine.

## License of contributions

LabLantern is published under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). By submitting a contribution
you confirm that you have the right to submit it, and you agree that it is licensed under the same terms and that
the project owner, Noah Eberhardt, may also license it under other terms, including commercial ones.
