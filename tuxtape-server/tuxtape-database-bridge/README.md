# tuxtape-database-bridge

This library serves as the "bridge" to the SQL database backend used for
`tuxtape-server`. Most of the code here is boilerplate ORM code either generated
by `diesel`'s CLI tool (`src/schema.rs`) or `dsync` at build time.

Any handlers should not be defined inside this library. This should only serve
as an interface to the database, not an implementation of usage of the database.
