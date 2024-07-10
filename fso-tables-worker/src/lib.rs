use serde::{Deserialize, Serialize};
use worker::*;
use email_address::*;

/*
const USER_LEVEL_OWNER: u8 = 0;
const USER_LEVEL_ADMIN: u8 = 1; // Able to upgrade other users to a maintainer
const USER_LEVEL_MAINTAINER: u8 = 2; // Able to make changes to table docs
const USER_LEVEL_VIEWER: u8 = 3; // Just here until someone upgrades to a maintainer level  */
const DB_NAME: &str = "fso_table_database";

#[derive(Deserialize, Serialize)]
struct GenericResponse {
    status: u16,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct BasicCount {
    the_count: i32,
}



//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context,) -> Result<Response> {
    Router::new()
        .get_async("/", root_get)
        .get_async("/users", user_stats_get)       // No Post, put, patch, or delete for overarching category
        .post_async("/users/register", user_register_new)
        .get_async("/users/myaccount", user_get_details)/* 
        .put_async(api_insufficent_permissions).patch(api_insufficent_permissions).delete(deactivate_user))
        .route("/users/:username/passwordchange", put(user_change_password).patch(user_change_password).delete(api_insufficent_permissions))    // No post, get or delete for password
        .route("/users/:username/upgrade", put(upgrade_user_permissions).patch(upgrade_user_permissions))
        .route("/users/:username/downgrade", put(downgrade_user_permissions).patch(downgrade_user_permissions))
        .route("/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
        .route("/users/activate/:code", post(confirm_email_address)) */
        .or_else_any_method_async("/", err_api_fallback)
        .run(req, env)
        .await
}


pub async fn root_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    Response::from_json(&GenericResponse {
    status: 200,
    message: "You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors.\n\nThis API is currently under construction!".to_string(),
    })
}

pub async fn user_stats_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    let db = _ctx.env.d1(DB_NAME);

    match &db{
        Ok(connection) => {
            let query = connection.prepare("SELECT COUNT(*) as the_count FROM users WHERE active = 1");
            match query.first::<BasicCount>(None).await {
                Ok(r) => {
                    match r {
                        Some(r2) => Response::from_json(&r2) ,
                        None => return err_specific("Internal server erorr, query returned no count".to_string()).await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }
        }
        Err(e) => return err_specific(e.to_string()).await,
    }            
}

#[derive(Serialize, Deserialize)]
struct EmailSubmission{
    email: String,
}

pub async fn user_register_new(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let submission = req.json::<EmailSubmission>().await;
    if submission.is_err() {
        return err_bad_request().await;
    }
    
    let email = submission.unwrap();

    if !EmailAddress::is_valid(&email.email){
        return Response::from_json(&GenericResponse {
            status: 200,
            message: "Email address is not in the right format".to_string(),
        })
    }

    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(db1) => {
            match db_does_user_exists(&email.email, &db1).await {
                Ok(_) => {},
                Err(e) => return err_specific(e.to_string()).await,
            };
            
            let statement = db1.prepare("INSERT INTO users (username, role, active) VALUES (?, 3, 0)").bind(&[email.email.into()]);
            match &statement {
                Ok(q) => {
                    if let Err(e) = q.run().await {
                        return err_specific(e.to_string()).await;
                    }

                    // TODO! need to send a confirmation email here

                    return Response::from_json(&GenericResponse {
                        status: 200,
                        message: "User created!".to_string(),
                    })    
                },
                Err(e) => return err_specific(e.to_string()).await,
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }

}

#[derive(Serialize, Deserialize)]
pub struct UserDetails{
    username: String,
    role: i32,
    contribution_count: i32,
    active: i32,
}


pub async fn user_get_details(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    if let Some(resp) = header_has_token(&req).await{
        return resp;
    }

    if let Some(resp) = header_has_username(&req).await {
        return resp;
    }
  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            if !header_token_is_valid(&req, &db).await {
                return err_not_logged_in().await
            } else {
                if let Some(username) = req.headers().get("username").unwrap(){
                    match db_get_user_details(&username, &db).await {
                        Ok(res) => return Response::from_json(&res),
                        Err(e) => return err_specific(e.to_string()).await,
                    }    
                } else {
                    return err_specific("Header didn't have username the second time?".to_string()).await
                }

            }            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn deactivate_user(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            // AUTHENTICATE USER HERE
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_change_password(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            // AUTHENTICATE USER HERE
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_upgrade_user_permissions(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            // AUTHENTICATE USER HERE
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_downgrade_user_permissions(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            // AUTHENTICATE USER HERE
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_add_email(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            // AUTHENTICATE USER HERE
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_confirm_email_address(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(_) => {
            
            return err_api_under_construction().await            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

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


//pub async fn table_get_details(params(":tid")) -> &'static str {
//    "FINISH ME! = Table get details"
//}

#[derive(Serialize, Deserialize)]
struct Enabled{
    active: i32,
}

// SECTION!! generic database tasks 
pub async fn db_does_user_exists(email: &String, db: &D1Database) -> Result<bool> {
    let query = db.prepare("SELECT active FROM users WHERE username = ?").bind(&[email.into()]).unwrap();

    match query.first::<Enabled>(None).await {
        Ok(r) => {
            match r {
                Some(_) => return Ok(true),
                None => return Ok(false),
            }
        },
        Err(e) => return Err(e),
    }
}

pub async fn db_get_user_details(email: &String, db: &D1Database) -> Result<UserDetails> {
    let query = db.prepare("SELECT username, role, contribution_count, active FROM users WHERE username = ?").bind(&[email.into()]).unwrap();

    match query.first::<UserDetails>(None).await {
        Ok(r) => {
            match r {
                Some(ud) => return Ok(ud),
                None => Err("Database error! Could not find user despite already being verified!".into()),
            }
        },
        Err(e) => return Err(e),
    }
}

// SECTION!! generic server tasks
pub async fn  header_has_token(req: &Request) -> Option<Result<Response>> {
    match req.headers().has("ganymede_token"){
        Ok(res) => {
            if res { 
                return None 
            } else {
                return Some(err_not_logged_in().await)
            }        
        },
        Err(e) => return Some(err_specific(e.to_string()).await),
    }
}

pub async fn header_has_username(req: &Request) -> Option<Result<Response>>{
    match req.headers().has("username"){
        Ok(res) => {
            if res { 
                return None 
            } else {
                return Some(err_bad_request().await)
            }        
        },
        Err(e) => return Some(err_specific(e.to_string()).await),
    }
}

// this is going to be a big one.  We'll need to 1. Lookup an entry on username/tokens
// 2. Compare the token they gave us and see if it matches the username. 
// 3. See if the token is still valid.
pub async fn header_token_is_valid(_req: &Request, _db: &D1Database) -> bool {
    true
}

// SECTION!! Body/Server Failure Responses
pub async fn err_insufficent_permissions() -> worker::Result<Response> {
    Response::error("This operation is not authorizable via our API at your access level.", 403)    
}

pub async fn err_not_logged_in() -> worker::Result<Response> {
    Response::error("You must be logged in to access this ednpoint.", 403)
}

pub async fn err_api_fallback(_: Request, _: RouteContext<()>) -> worker::Result<Response> {
    Response::error("A method for this API route does not exist.", 404)    
}

pub async fn err_api_under_construction() -> worker::Result<Response> {
    Response::error("This endpoint is under construction.", 403)    
}

pub async fn err_bad_request() -> worker::Result<Response> {
    Response::error("Bad request, check your json input.", 400)    
}

pub async fn err_specific(e: String) -> worker::Result<Response> {
    Response::error(&e, 500)    
}

/*
use worker::*;

#[derive(Deserialize)]
struct Registration {
	email: String,
	password: String,
}
*/
