use axum::
    {
        {
        routing::{get, post, patch, delete},
        Router,
        },
    http::StatusCode
    };
use tower_service::Service;
use worker::*;
use serde::{Deserialize, Serialize};

/*#[derive(Serialize, Deserialize)]
struct PasswordResetRequest {
	thing_id: String,
	desc: String,
	num: u32,
}*/

//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.

fn router() -> Router {
    Router::new()
    .route("/", get(root))
    .route("/users", get(user_stats_get))       // No Post, get, put, patch, or delete for overarching category
    .route("/users/:username", 
        post(user_register_new).get(user_get_details).put(api_insufficent_permissions).patch(api_insufficent_permissions).delete(deactivate_user))
    .fallback(api_fallback)
}

/*
    .route("/tables", get(table_stats_get))
    .route("/tables/:tid", get(table_get_details))
    .route("/tables", post(table_post))
    .route("/tables", patch(table_stats_get))
    .route("/tables", get(table_stats_get))
    .route("/tables", get(table_stats_get))
    .route("/tables", get(table_stats_get))
    .route("/tables/", get(user))
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
struct Thing {
	thing_id: String,
	desc: String,
	num: u32,
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