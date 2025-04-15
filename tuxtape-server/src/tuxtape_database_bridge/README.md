# tuxtape_database_bridge

This library serves as the "bridge" to the SQL database backend used for
`tuxtape-server`.

# Models

Models which represent the data stored in the database are defined in `models/`.

# gRPC

All handlers for database-related gRPC requests are located within the `grpc`
module. These handlers take in `T` for `tonic` `Request<T>` types (the inner
message) and return a `T` for `tonic` `Response<T>` types.
