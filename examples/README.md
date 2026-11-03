# OOBscan library examples

Small, compiling snippets showing how to extend OOBscan as a library. They are
part of the module, so `go build ./examples/...` and `go vet ./examples/...`
ensure they compile, but none is wired into the scanner. They are reference
implementations for contributors.

| File | Shows |
|---|---|
| [`register_check.go`](register_check.go) | Registering a security check with `check.Register` and writing a `Run` function that reuses collected evidence |
| [`add_creds.go`](add_creds.go) | Adding a default-credential row to `creds.Table` and reading it back with `creds.CredsFor` |
| [`add_device_class.go`](add_device_class.go) | Adding a product to `oob.Registry` and the `oob.Category` -> `engine.DeviceClass` mapping |

In a real contribution:

- A **check** registers itself from an `init()` inside `pkg/check` (not from
  a standalone function) so it is present at program start. The examples export
  a function instead, to stay callable and testable without duplicate-registration
  panics.
- A **credential** is a literal appended to `creds.Table` in
  `pkg/creds/table.go`.
- A **device** is a literal appended to `oob.Registry` in
  `pkg/oob/registry.go`; a genuinely new `oob.Category` also needs a case in
  `pkg/identify/class.go`.

Follow the [assessment safety guidance](../README.md#authorized-use-and-operational-safety).
Describe each check's evidence, limitations, and remediation, and test that
credential checks honor the login opt-out. Document every state-changing request
and keep disruptive diagnostics explicitly selected by the operator.
