use crate::models::{User, UserRegister};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use sqlx::{postgres::PgPoolOptions, Error, PgPool};
use uuid::Uuid;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        Ok(Self {pool})
    }

    pub async fn init_schema(&self) -> Result<(), Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )"
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    pub async fn user_exists(&self, email: &str) -> Result<bool, Error> {
        let record = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) as exists",
            email
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(record.exists.unwrap_or(false))
    }
    
    pub async fn create_user(&self, user_data: &UserRegister) -> Result<Uuid, Error> {
        let password_hash = hash(&user_data.password, DEFAULT_COST)
            .map_err(|_| Error::RowNotFound)?;
            
        let user_id = Uuid::new_v4();
        
        sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash, role, created_at) 
             VALUES ($1, $2, $3, $4, $5, $6)",
            user_id,
            user_data.username,
            user_data.email,
            password_hash,
            "user", // current default role
            Utc::now()
        )
        .execute(&self.pool)
        .await?;
        
        Ok(user_id)
    }
    
    // Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, email, password_hash, role, created_at FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn verify_user_exists(&self, user_id: Uuid) -> Result<bool, Error> {
        let record = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1) as exists",
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(record.exists.unwrap_or(false))
    }
    
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        verify(password, hash)
    }
}
