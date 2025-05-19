# tuxtape_database_bridge

This library serves as the "bridge" to the SQL database backend used for
`tuxtape-server`.

# grpc

The `grpc` module contains all handlers for database-related gRPC requests. 

# handlers

The `handlers` module handles data insertion and reads to/from the database
based on the inner messages within the requests handled by the `grpc` module.
