use crate::{
    auth::JWTAuth,
    db::Database,
    models::{ApiResponse, UserLogin, UserRegister, Claims},
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use uuid::Uuid;

pub struct AppState {
    pub db: Database,
    pub auth: JWTAuth,
}

pub async fn register(
    state: web::Data<AppState>,
    user_data: web::Json<UserRegister>,
) -> impl Responder {
    match state.db.user_exists(&user_data.email).await {
        Ok(true) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error("User already exists"))
        }
        Ok(false) => {}
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"))
        }
    }

    match state.db.create_user(&user_data).await {
        Ok(_) => HttpResponse::Created().json(ApiResponse::<()>::success(
            "User registered successfully",
            (),
        )),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to register user"))
        }
    }
}

pub async fn login(
    state: web::Data<AppState>,
    login_data: web::Json<UserLogin>,
) -> impl Responder {
    // Find user by email
    let user = match state.db.get_user_by_email(&login_data.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid credentials"))
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"))
        }
    };

    // Verify the password
    let is_valid = match Database::verify_password(&login_data.password, &user.password_hash) {
        Ok(valid) => valid,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Password verification failed"))
        }
    };

    if !is_valid {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid credentials"));
    }


    match state.auth.generate_token(user.id, &user.role) {
        Ok(token_response) => {
            HttpResponse::Ok().json(ApiResponse::success("Login successful", token_response))
        }
        Err(_) => HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Token generation failed")),
    }
}

pub async fn authenticate_request(
    req: &HttpRequest,
    state: &web::Data<AppState>,
) -> Result<Claims, HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Invalid or missing Authorization header"))
        })?;

    let token = JWTAuth::extract_token(auth_header).ok_or_else(|| {
        HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid Authorization format"))
    })?;

    let claims = state.auth.validate_token(token).map_err(|_| {
        HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid token"))
    })?;

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid user ID"))
    })?;

    let user_exists = state.db.verify_user_exists(user_id).await.map_err(|_| {
        HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"))
    })?;

    if !user_exists {
        return Err(
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error("User no longer exists"))
        );
    }

    Ok(claims)
}

pub async fn some_operation(
    req: HttpRequest,
    state: web::Data<AppState>
) -> impl Responder {
    let claims = match authenticate_request(&req, &state).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    HttpResponse::Ok().json(ApiResponse::success(
        "Successfully accessed",
        serde_json::json!({
            "user_id": claims.sub,
            "role": claims.role
        }),
    ))
}
