use serde::{Deserialize, Serialize};
use worker::*;

/*
const USER_LEVEL_OWNER: u8 = 0;
const USER_LEVEL_ADMIN: u8 = 1; // Able to upgrade other users to a maintainer
const USER_LEVEL_MAINTAINER: u8 = 2; // Able to make changes to table docs
const USER_LEVEL_VIEWER: u8 = 3;  */
const DB_NAME: &str = "fso_table_database";

#[derive(Debug, Deserialize, Serialize)]
struct GenericResponse {
    status: u16,
    message: String,
}


//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context,) -> Result<Response> {
    Router::new()
        .get_async("/", root_get)
        .get_async("/users", user_stats_get)       // No Post, put, patch, or delete for overarching category
    /*    .route("/users/:username", 
            post(user_register_new).get(user_get_details).put(api_insufficent_permissions).patch(api_insufficent_permissions).delete(deactivate_user))
        .route("/users/:username/passwordchange", put(user_change_password).patch(user_change_password).delete(api_insufficent_permissions))    // No post, get or delete for password
        .route("/users/:username/upgrade", put(upgrade_user_permissions).patch(upgrade_user_permissions))
        .route("/users/:username/downgrade", put(downgrade_user_permissions).patch(downgrade_user_permissions))
        .route("/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
        .route("/users/:username/activateemail/:code", post(confirm_email_address)) */
        .run(req, env)
        .await
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


pub async fn root_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    Response::from_json(&GenericResponse {
    status: 200,
    message: "You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors.\n\nThis API is currently under construction!".to_string(),
    })
}

pub async fn user_stats_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    let db = _ctx.env.d1(DB_NAME);
    let query_result: std::result::Result<_, _>;

    match &db{
        Ok(connection) => {
                let query = connection.prepare("SELECT COUNT(*) FROM users WHERE active = 1");
                query_result = query.run().await.unwrap().results::<i32>();
            },
        Err(e) => return Response::from_json(&GenericResponse {
            status: 500,
            message: e.to_string(),
            }),
    }

    match &query_result{
        Ok(number) => Response::from_json(&GenericResponse {
            status: 200,
            message: number[0].to_string(),
            }),
	    Err(e) => Response::from_json(&GenericResponse {
            status: 500,
            message: e.to_string(),
            }),
	}


}

//pub async fn table_get_details(params(":tid")) -> &'static str {
//    "FINISH ME! = Table get details"
//}

// Failures
pub async fn err_insufficent_permissions() -> worker::Result<Response> {
    Response::from_json(&GenericResponse {
        status: 403,
        message: "This operation is not authorizable via our API at your access level.".to_string(),
    })
}

pub async fn err_api_fallback() -> worker::Result<Response> {
    Response::from_json(&GenericResponse {
        status: 404,
        message: "A method for this API route does not exist.".to_string(),
    })
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