use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::users;

#[derive(Queryable, Serialize, Deserialize, Debug, Selectable)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    #[serde(skip)]
    pub password: String,
    pub profile_picture: Option<String>,
    pub role: String,
    pub status: String,
}

#[derive(Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub password: String,
    pub profile_picture: Option<String>,
    pub role: String,
    pub status: String,
}

#[derive(Deserialize, AsChangeset)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub name: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub profile_picture: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
}
