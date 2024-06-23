use axum::
    {
        http::StatusCode,
        routing::{get, post, patch, delete},
        Router,
    };
use tower_service::Service;
use worker::*;
use serde::{Deserialize, Serialize};

const USER_LEVEL_OWNER: u8 = 0;
const USER_LEVEL_ADMIN: u8 = 1; // Able to upgrade other users to a maintainer
const USER_LEVEL_MAINTAINER: u8 = 2; // Able to make changes to table docs
const USER_LEVEL_VIEWER: u8 = 3; 
const DB_NAME: str = "fso-modoption-d1-db";

/*#[derive(Serialize, Deserialize)]
struct PasswordResetRequest {
	thing_id: String,
	desc: String,
	num: u32,
}*/

//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.

fn router() -> Router {
    let db = ctx.env.d1(DB_NAME)?;

    Router::new()
    .route("/", get(root))
    .route("/users", get(user_stats_get))       // No Post, put, patch, or delete for overarching category
    .route("/users/:username", 
        post(user_register_new).get(user_get_details).put(api_insufficent_permissions).patch(api_insufficent_permissions).delete(deactivate_user))
    .route("/users/:username/passwordchange", put(user_change_password).patch(user_change_password).delete(api_insufficent_permissions))    // No post, get or delete for password
    .route("/users/:username/upgrade", put(upgrade_user_permissions).patch(upgrade_user_permissions))
    .route("/users/:username/downgrade", put(downgrade_user_permissions).patch(downgrade_user_permissions))
    .route("/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
    .route("/users/:username/activateemail/:code", post(confirm_email_address))
    .fallback(api_fallback)
}

/* 
user_register_new
user_get_details
deactivate_user
user_change_password
upgrade_user_permissions
downgrade_user_permissions
add_email
confirm_email_address
*/

/*
    .route("/tables", get(table_stats_get).post(table_post).delete(api_insufficent_permissions))
    .route("/tables", )
    .route("/tables", get(table_stats_get))
    .route("/tables", get(table_stats_get))
    .route("/tables", get(table_stats_get))
    .route("/tables/:tid", get(table_get_details))
 */
/*
    .route("/deprecations/", get(user))
 */

 //:id for the taco rocket of doom

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    Ok(router().call(req).await?)
}

pub async fn root() -> &'static str {
    "You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors."
}

pub async fn user_stats_get() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "API has not been set up to retrieve overall user details")
}

pub async fn deactivate_user() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "API has not been set up to deactivate users")
}

pub async fn table_stats_get() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "API has not been set up to retrieve overall table details")
}


//pub async fn table_get_details(params(":tid")) -> &'static str {
//    "FINISH ME! = Table get details"
//}

// Failures
pub async fn api_insufficent_permissions() -> (StatusCode, &'static str) {
    (StatusCode::FORBIDDEN, "This operation is not authorizable via our API")
}

pub async fn api_fallback() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "API Route Not Found")
}
/*
use worker::*;

#[derive(Deserialize)]
struct Registration {
	email: String,
	password: String,

}

#[event(fetch, respond_with_errors)]
pub async fn main(request: Request, env: Env, _ctx: Context) -> Result<Response> {
	Router::new()
		.get_async("/:id", |_, ctx| async move {
			let id = ctx.param("id").unwrap()?;
			let d1 = ctx.env.d1("things-db")?;
			let statement = d1.prepare("SELECT * FROM things WHERE thing_id = ?1");
			let query = statement.bind(&[id])?;
			let result = query.first::<Thing>(None).await?;
			match result {
				Some(thing) => Response::from_json(&thing),
				None => Response::error("Not found", 404),
			}
		})
		.run(request, env)
		.await
} */