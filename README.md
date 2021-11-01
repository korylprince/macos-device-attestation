[![pkg.go.dev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/korylprince/macos-device-attestation)

# About

`macos-device-attestation` is a library to help build a macOS device attestation service. An on-device client can use this library to attest to a server using this library that it's running as root on the particular device (tied to a serial number).

# How It Works

At a high level, a server creates an `attest.AttestationService` and mounts it's `PlaceHandler` and `FileStoreHandler` at URLs accessible by the client. When a client requests attestation, the server uses a `transport.Transport` (see below) to securely place a token only readable by root on the client and tells the client where to read it from.

The server can protect any other URLs with the `AttestationService`'s `Middleware` (or built-in `JSONMiddleware` helper). The client sends the token in the Authorization header, and the Middleware authenticates the token and places the serial number in the `http.Request`'s context (with key `attest.ContextKeySerial`).

At a lower level, `attest.AttestationService` is backed by several interfaces:

* `tokenstore.TokenStore`: generates and authenticates tokens. Currently there are two implementations:
  * `mem.TokenStore`: in-memory, bounded cache storage of tokens
  * `jwt.TokenStore`: generates stateless, expirable JWT tokens
* `filestore.FileStore`: stores and retreives files for use by a `transport.Transport`. Currently there is one implementation:
  * `mem.FileStore`: in-memory, bounded, auto-expiring cache storage of files
* `transport.Transport`: places a secret on a device. Currently there is one implementation:
  * `mdm.Transport`: uses an `mdm.MDM` (see below) to place the secret on a device via an InstallEnterpriseApplication command

`mdm.MDM` is itself an interface that currently has one implementation:
* `micromdm.MDM`: uses MicroMDM's API

This library is meant to be extensible. Some examples of extending it:

* Use the token long-term or as a stepping-stone to more advanced PKI
* Implement an `mdm.MDM` for your MDM (assuming it has an API!)
* Implement a non-MDM `transport.Transport`. e.g. with SSH. Make sure your Transport can absolutely target the correct device and the secret stays secure!
* Create a `filestore.FileStore` that can be shared by multiple servers

PRs are welcome for implementations that are useful for a wide audience!

# Usage

See the [server](./examples/server/server.go) and [client](./examples/client/client.go) examples.

# Issues

If you have any issues or questions [create an issue](https://github.com/korylprince/macos-device-attestation/issues).
