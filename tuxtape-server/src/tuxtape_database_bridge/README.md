# tuxtape_database_bridge

This library serves as the "bridge" to the SQL database backend used for
`tuxtape-server`.

# Models

Models which represent the data stored in the database are defined in `models/`.

# gRPC

All handlers for database-related gRPC requests are located within the `grpc`
module. These handlers take in `T` for `tonic` `Request<T>` types (the inner
message) and return a `T` for `tonic` `Response<T>` types.

## grpc/service.rs

The `service` module consumes `DatabaseService` `Request` messages and returns
`Response` messages.

## grpc/handlers

The `handlers` module takes in the individual Protobuf message types contained
within the `Request` messages and queries the database from them, returning
the relevant `Response` messages.
