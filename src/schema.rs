// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        name -> Varchar,
        email -> Varchar,
        password -> Varchar,
        profile_picture -> Nullable<Varchar>,
        role -> Varchar,
        status -> Varchar,
    }
}
