use axum::async_trait;

use sqlx::{Executor as _, SqlitePool};
use std::{error::Error, fs::OpenOptions, str::FromStr};
use uuid::Uuid;

use super::data_model::{AuthorizationId, HashedPassword};

#[async_trait]
pub trait UserDatabase: Clone + Send + Sync + 'static {
    async fn build() -> Result<Self, sqlx::Error>;
    /// Create a user in the database, the username must be unique. It will assign a Uuid ( AuthorizationId ) to the user.
    /// Make sure to hash the password before you insert into the database.
    async fn create_user(
        &self,
        contact: &str,
        username: &str,
        unhashed_password: &str,
    ) -> Result<AuthorizationId, sqlx::Error>;
    /// Deletes a user given an authorization id.
    async fn delete_user(&self, auth_id: AuthorizationId) -> Result<(), sqlx::Error>;
    /// Finds a User based on their authorization id, and then for any Some(argument) will update the associated field.
    /// Verification is a one way operation, so this sets verified to 1 if verified is true, but if verified is false it does nothing.
    async fn edit_user(
        &self,
        auth_id: AuthorizationId,
        contact: Option<String>,
        username: Option<String>,
        unhashed_password: Option<&str>,
        verified: bool,
    ) -> Result<(), sqlx::Error>;
    /// This will match the username + password against the database.
    /// It will return an Some(AuthorizationId) if matched, None if there was no match.
    async fn auth_id_by_username_password(
        &self,
        username: String,
        unhashed_password: String,
    ) -> Result<AuthorizationId, sqlx::Error>;
    /// Authorization id must always be valid if returned.
    async fn auth_id_by_contact(&self, contact: String) -> Result<AuthorizationId, Box<dyn Error>>;
}

#[async_trait]
impl UserDatabase for SqlitePool {
    #[tracing::instrument(err)]
    async fn build() -> Result<SqlitePool, sqlx::Error> {
        let path = "auth.db";
        OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .truncate(false)
            .open(path)?;
        let conn = SqlitePool::connect(path).await?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                auth_id TEXT PRIMARY KEY,  -- UUID stored as TEXT
                contact TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0 -- 0 is not verified, 1 is verified.
            )
        "#,
        )
        .await?;

        // Unique columns are already indexed, otherwise we'd index it here.

        Ok(conn)
    }
    #[tracing::instrument(skip(self), err)]
    async fn create_user(
        &self,
        contact: &str,
        username: &str,
        unhashed_password: &str,
    ) -> Result<AuthorizationId, sqlx::Error> {
        let auth_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO users (auth_id, contact, username, password)
            VALUES ( ?1, ?2, ?3, ?4)
        "#,
        )
        .bind(auth_id.to_string())
        .bind(contact)
        .bind(username)
        .bind(&*HashedPassword::new(unhashed_password))
        .execute(self)
        .await?;
        Ok(AuthorizationId::new(auth_id))
    }
    #[tracing::instrument(skip(self), err)]
    async fn delete_user(&self, auth_id: AuthorizationId) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM users WHERE auth_id = ?;
        "#,
        )
        .bind(auth_id.map(|id| id.to_string()))
        .execute(self)
        .await?;
        Ok(())
    }
    #[tracing::instrument(skip(self), err)]
    async fn edit_user(
        &self,
        auth_id: AuthorizationId,
        contact: Option<String>,
        username: Option<String>,
        unhashed_password: Option<&str>,
        verified: bool,
    ) -> Result<(), sqlx::Error> {
        // Create a vector to hold the query parts and parameters
        let mut set_clauses = Vec::new();
        let mut params = Vec::new();

        // Add fields to update if they are provided
        if let Some(contact) = contact {
            set_clauses.push("contact = ?");
            params.push(contact);
        }
        if let Some(username) = username {
            set_clauses.push("username = ?");
            params.push(username);
        }
        if let Some(password) = unhashed_password {
            set_clauses.push("password = ?");
            params.push(HashedPassword::new(password).clone());
        }

        if verified {
            set_clauses.push("verified = ?");
            params.push(1.to_string());
        }
        // Return early if there's nothing to update
        if set_clauses.is_empty() {
            return Ok(()); // No fields to update, nothing to do
        }

        // Build the final query
        let query = format!(
            "UPDATE users SET {} WHERE auth_id = ?",
            set_clauses.join(", ")
        );

        // Prepare the query and bind the parameters
        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        query_builder = query_builder.bind(auth_id.map(|id| id.to_string()));

        // Execute the query
        query_builder.execute(self).await?;

        Ok(())
    }
    #[tracing::instrument(skip(self), err)]
    async fn auth_id_by_username_password(
        &self,
        username: String,
        unhashed_password: String,
    ) -> Result<AuthorizationId, sqlx::Error> {
        if let Some((auth_id, db_password)) = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT auth_id, password
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(self)
        .await?
        {
            if HashedPassword::from_hashed_password(db_password)
                .compare_unhashed(&unhashed_password)
            {
                Ok(AuthorizationId::new(
                    Uuid::from_str(&auth_id).unwrap_or_default(),
                ))
            } else {
                // wrong password error?
                Ok(AuthorizationId::new(Uuid::default()))
            }
        } else {
            // no user found error?
            Ok(AuthorizationId::new(Uuid::default()))
        }
    }
    #[tracing::instrument(skip(self), err)]
    async fn auth_id_by_contact(&self, contact: String) -> Result<AuthorizationId, Box<dyn Error>> {
        let auth_id = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT auth_id
            FROM users
            WHERE contact = ?
            "#,
        )
        .bind(contact)
        .fetch_one(self)
        .await?;
        let auth_id = Uuid::from_str(&auth_id.0)?;

        Ok(AuthorizationId::new(auth_id))
    }
}
