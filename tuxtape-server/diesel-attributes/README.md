# diesel-attributes

This is a very small procedural macro library used to reduce code duplication in
`tuxtape-server`'s database models. Currently, Rust requires that procedural 
macros be defined in a separate library as they get run in the preprocesor.
Additionally, there does not seem to be any way to combine mutiple attributes
into one meta-attribute without using procedural macros.

This library gives us three custom attributes for `diesel` models:
`diesel_model_fetch`, `diesel_model_insert`, and `diesel_model_update`.
In `tuxtape-server`, we currently want to support both SQLite and PostgreSQL,
so we need to operate on the subset of what commands both of these backends
support. In order to get `diesel` to check that we're writing handlers which
are compatible with both backends, every model needs to have the attributes:
```
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(check_for_backend(diesel::pg::Pg))]
```

Additionally, all fetch, insert, and update models in our program require some 
common attributes, so this gives us the ability to condense four lines of 
repeated code into one. This also provides some extra safety, as forgetting a 
line like `#[diesel(check_for_backend(diesel::sqlite::Sqlite))]` may allow for
Postgres-specific operations to be called on a Sqlite backend, which is an issue
we can prevent at compile time if we're sure that the appropriate attributes are
always applied.
