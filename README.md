# agentx

This library implements all PDU types and encodings according to
[RFC2741](https://datatracker.ietf.org/doc/html/rfc2741). It provides Rust idiomatic abstractions wherever
possible and allows serialization and deserialization to/from wire compatible bytes.

## Documentation
The typical documentation including examples can be found on [docs.rs/agentx](https::/docks.rs/agentx). This
library provides all the types and PDUs the standard defines, but does not provide any higher level
abstractions that do connection handling or AgentX session handling. A full featured AgentX sub-agent
implementation can be found as part of `drbd-reactor`
[here](https://github.com/LINBIT/drbd-reactor/blob/master/src/plugin/agentx.rs). This should provide enough
hints to implement a sub-agent on your own. Because of the multi-threaded nature of `drbd-reactor`, the
implementation might look a bit overwhelming, a simple single-threaded sub-agent should be doable ways easier.
Good starting points are `agentx_handler()` for establishing a session and `Metrics::get()` and
`Metrics::get_next()` for actual PDU handling.

## License
Licensed under either of Apache License, Version 2.0 or MIT license at your option.
