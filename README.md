# Webauthn

**Alpha Software Warning!**

This software package is in an alpha stage. This means the development team is not investing any effort to provide backward compatibility between alpha releases. This software will continue to be released as alpha until it is considered stable at which point this warning will be removed.

## ALPHA TODO LIST

- [] Fully automated test suite.
- [] Manual testing for non-usb based security keys
- [] Documentation on how to use, configure and test this library.
- [] Create an application that demonstrates how to use this library within the context of a web framework.
- [] Create a js library that handles the front-end logic for translating the server data to a format for the browser to understand.
- [] Allow people to configure additional root CA certificates from security key manufacturers.
- [] Make sure that we are correctly checking that certificates do not appear on their authority's certificate revocation list.
- [] Integrate with the FIDO metadata service (optional)
- [] Community feedback on API design and integration challenges.
- [] Look into FIDO certification for this library

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `webauthn` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:webauthn, "~> 0.0.1"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/webauthn](https://hexdocs.pm/webauthn).

