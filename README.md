# quarshell-driver-vm

MicroVM compute driver and guest runtime for Quarshell.

The module provides VM lifecycle, OCI image handling, worker control, guest agent, terminal, networking and recovery components. Gateway and target-host acceptance status is documented in the [compatibility guide](https://klorq.github.io/sandbox.dev/reference/openshell-compatibility/).

## Install

```sh
go get github.com/KLORQ/quarshell-driver-vm@latest
```

## Development

```sh
go test ./...
```

Requires Go 1.27 or newer. See the [Quarshell documentation](https://klorq.github.io/sandbox.dev/) for product guides and compatibility status.

## License

Apache-2.0.
