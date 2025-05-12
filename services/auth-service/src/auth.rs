use std::usize;
use crate::models::{Claims, TokenResponse};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use uuid::Uuid;

pub struct JWTAuth {
    jwt_secret: String,
}

impl JWTAuth {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    pub fn generate_token(&self, user_id: Uuid, role: &str) -> Result<TokenResponse, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let expires_at = (now + Duration::hours(24)).timestamp() as usize;

        let claim = Claims {
            sub: user_id.to_string(),
            exp: expires_at,
            iat: now.timestamp() as usize,
            role: role.to_string(),
        };

        let token = encode(
            &Header::default(), 
            &claim, 
            &EncodingKey::from_secret(self.jwt_secret.as_bytes())
        )?;

        Ok(TokenResponse {
            token,
            token_type: "Bearer".to_string(),
            expires_in: expires_at,
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        log::debug!("Token: {:?}", token);

        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(token_data) => {
                log::debug!("TOKEN CLAIMS: {:?}", token_data);
                Ok(token_data.claims)
            }
            Err(err) => {
                log::error!("JWT decode failed: {:?}", err);
                Err(err)
            }
        }
    }
    
    // Extract from header 
    pub fn extract_token(auth_header: &str) -> Option<&str> {
        if auth_header.starts_with("Bearer ") {
            Some(auth_header.trim_start_matches("Bearer ").trim())
        } else {
            None
        }
    }
    
}
