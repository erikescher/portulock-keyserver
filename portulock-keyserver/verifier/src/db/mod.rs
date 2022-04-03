use std::fmt::{Debug, Formatter};

use rocket_contrib::database;

pub mod diesel_sqlite;
mod diesel_types;
mod schema;

#[database("sqlite")]
pub struct SubmitterDBConn(pub diesel::SqliteConnection);

impl Debug for SubmitterDBConn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubmitterDBConn") // TODO add SQLite url
    }
}
