use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Expr, parse_macro_input};

/// A macro to combine the common derives and diesel macros for
/// a fetchable model.
/// "Fetchable" in this case means a model that directly represents
/// a row in the database.
#[proc_macro_attribute]
pub fn diesel_model_fetch(arg: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let table = parse_macro_input!(arg as Expr);

    let expanded = quote! {
        #[derive(Queryable, Identifiable, Selectable, PartialEq, Debug)]
        #[diesel(check_for_backend(diesel::sqlite::Sqlite))]
        #[diesel(check_for_backend(diesel::pg::Pg))]
        #[diesel(table_name = #table)]
        #input
    };

    expanded.into()
}

/// A macro to combine the common derives and diesel macros for
/// a new model we wish to insert into the database.
#[proc_macro_attribute]
pub fn diesel_model_insert(arg: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let table = parse_macro_input!(arg as Expr);

    let expanded = quote! {
        #[derive(Insertable, Debug)]
        #[diesel(check_for_backend(diesel::sqlite::Sqlite))]
        #[diesel(check_for_backend(diesel::pg::Pg))]
        #[diesel(table_name = #table)]
        #input
    };

    expanded.into()
}

/// A macro to combine the common derives and diesel macros for
/// a model that already exists in the database that we wish
/// to update.
#[proc_macro_attribute]
pub fn diesel_model_update(arg: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let table = parse_macro_input!(arg as Expr);

    let expanded = quote! {
        #[derive(AsChangeset, Debug)]
        #[diesel(check_for_backend(diesel::sqlite::Sqlite))]
        #[diesel(check_for_backend(diesel::pg::Pg))]
        #[diesel(table_name = #table)]
        #input
    };

    expanded.into()
}
