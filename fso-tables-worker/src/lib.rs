use serde::{Deserialize, Serialize};
use worker::*;
use email_address::*;
use regex::Regex;
use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2
};
use rand::*;
use lettre::{transport, Message, SmtpTransport, Transport,};
use lettre_email::{EmailBuilder, Mailbox};

mod secrets;

const DB_NAME: &str = "fso_table_database";    
const DB_ALLOWED_PASSWORD_CHARACTERS: &str = "[^0-9A-Za-z~! @#$%^&*()_\\-+={[}\\]|\\\\:;<,>.?/]";
const DB_MINIMUM_PASSWORD_LENGTH: usize = 8;

#[derive(PartialEq, PartialOrd)]
pub enum UserRole {
    OWNER = 0,
    ADMIN = 1, // Able to upgrade other users to a maintainer or downgrade maintainers to viewers
    MAINTAINER = 2, // Able to make changes to table fsdocs
    VIEWER = 3, // Waiting for someone to approve an upgrade to a maintainer level
}

#[derive(Deserialize, Serialize)]
struct BasicCount {
    the_count: i32,
}

//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context,) -> worker::Result<Response> {

    Router::new()
        .get_async("/", root_get)
        .get_async("/users", user_stats_get)       // No Post, put, patch, or delete for overarching category
        .post_async("/users/register", user_register_new)
        .get_async("/users/myaccount", user_get_details)
        .post_async("/users/myaccount/password", user_change_password)
        .delete_async("/users", deactivate_user)
        .post_async("/users/activate", activate_user).put_async("/users/activate", activate_user).patch_async("/users/activate", activate_user)
        /* 
        .route("/users/:username/upgrade", put(upgrade_user_permissions).patch(upgrade_user_permissions))
        .route("/users/:username/downgrade", put(downgrade_user_permissions).patch(downgrade_user_permissions))
        .route("/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
        .route("/users/activate/:code", post(confirm_email_address)) */
        .or_else_any_method_async("/", err_api_fallback)
        .run(req, env)
        .await

}


pub async fn root_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    Response::ok("You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors.\n\nThis API is currently under construction!".to_string())
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
        return Response::ok("Email address is not in the right format".to_string());
    }

    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(db1) => {
            match db_email_taken(&email.email, &db1).await {
                Ok(exists) => if exists {
                    return err_specific("User already exists".to_string()).await;
                },
                Err(e) => return err_specific(e.to_string()).await,
            };
            
            let statement = db1.prepare("INSERT INTO users (username, role, active, contribution_count) VALUES (?, 3, 0, 0)").bind(&[email.email.into()]);
            match &statement {
                Ok(q) => {
                    if let Err(e) = q.run().await {
                        return err_specific(e.to_string()).await;
                    }

                    // TODO! need to send a confirmation email here. No login without it!

                    return Response::ok("User created!".to_string());     
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


pub async fn deactivate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
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
            }

            if let Ok(username) = header_get_username(&req).await{
                match db_get_user_role(&username, &db).await {                 
                    Ok(authorizer_role) => {

                        match req.json::<EmailSubmission>().await {                                                        
                            Ok(target_user) =>{
                                match db_has_active_user(&target_user.email, &db).await {
                                    Ok(exists) => if !exists {
                                        return err_specific("User does not exist or may already be deactivated.".to_string()).await;
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,
                                };
                    
                                // Owners can only be deactivated by someone working directly with the database.
                                // But otherwise, you *can* deactivate yourself.
                                if target_user.email == username && authorizer_role != UserRole::OWNER {
                                    db_deactivate_user(&username, &db).await;
                                    return worker::Response::ok("User Deactivated")
                                }

                                // these two types are not allowed to deactivate other users
                                match authorizer_role {
                                    UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                    UserRole::VIEWER => return err_insufficent_permissions().await,
                                    _=> (),
                                }         
                                                                                        
                                match db_get_user_role(&target_user.email, &db).await { 
                                    Ok(target_user_role) => {
                                        if authorizer_role < target_user_role{
                                            db_deactivate_user(&target_user.email, &db).await;
                                            return worker::Response::ok("User Deactivated");
                                        } else {
                                            return err_insufficent_permissions().await;
                                        }
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,                                
                                }               
                            },
                            Err(_) => return err_bad_request().await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await, 
                }
            } else {
                return err_specific("Header didn't have username the second time?".to_string()).await
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn activate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
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
            }

            if let Ok(username) = header_get_username(&req).await{
                match db_get_user_role(&username, &db).await {                 
                    Ok(authorizer_role) => {

                        match req.json::<EmailSubmission>().await {                                                        
                            Ok(target_user) =>{
                                match db_has_active_user(&target_user.email, &db).await {
                                    Ok(exists) => if !exists {
                                        return err_specific("User does not exist or may already be deactivated.".to_string()).await;
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,
                                };
                    
                                // Owners can only be deactivated by someone working directly with the database.
                                // But otherwise, you *can* deactivate yourself.
                                if target_user.email == username{
                                    if authorizer_role == UserRole::OWNER {
                                        return err_insufficent_permissions().await
                                    } else {    
                                        db_deactivate_user(&username, &db).await;
                                        return worker::Response::ok("User Deactivated")
                                    }

                                }

                                // these two types are not allowed to deactivate other users
                                match authorizer_role {
                                    UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                    UserRole::VIEWER => return err_insufficent_permissions().await,
                                    _=> (),
                                }         
                                                                                        
                                match db_get_user_role(&target_user.email, &db).await { 
                                    Ok(target_user_role) => {
                                        if authorizer_role < target_user_role{
                                            db_deactivate_user(&target_user.email, &db).await;
                                            return worker::Response::ok("User Deactivated");
                                        } else {
                                            return err_insufficent_permissions().await;
                                        }
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,                                
                                }               
                            },
                            Err(_) => return err_bad_request().await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await, 
                }
            } else {
                return err_specific("Header didn't have username the second time?".to_string()).await
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

#[derive(Serialize, Deserialize)]
pub struct Password{
    password: String,
}

pub async fn user_change_password(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    if let Some(resp) = header_has_token(&req).await{
        return resp;
    }

    if let Some(resp) = header_has_username(&req).await {
        return resp;
    }

    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            if !header_token_is_valid(&req, &db).await {
                return err_not_logged_in().await
            }

            match req.json::<Password>().await{
                Ok(password) => {
                    if password.password.len() < DB_MINIMUM_PASSWORD_LENGTH {
                        return err_specific("Password is too short".to_string()).await
                    }
                    let search_set = Regex::new(DB_ALLOWED_PASSWORD_CHARACTERS).unwrap();
                    match search_set.find(&password.password) {
                        Some(_) => return err_specific("Disallowed password characters".to_string()).await,
                        None => (),
                    }

                    match header_get_username(&req).await {
                        Ok(username) =>
                            match hash_password(&username, &password.password).await {
                                Ok(hash) => (),//db_set_new_pass,
                                Err(_) => return err_specific("Hashing function failed.".to_string()).await,                            
                            },
                        Err(_) => return err_specific("Header didn't have username the second time?".to_string()).await
                    }
                },
                Err(_) => return err_bad_request().await,
            }

            return err_api_under_construction().await
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_upgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
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
            }

            if let Ok(username) = header_get_username(&req).await{
                match db_get_user_role(&username, &db).await {                 
                    Ok(authorizer_role) => {

                        match req.json::<EmailSubmission>().await {                                                        
                            Ok(target_user) =>{
                                match db_has_active_user(&target_user.email, &db).await {
                                    Ok(exists) => if !exists {
                                        return err_specific("User does not exist or may be deactivated.".to_string()).await;
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,
                                };
                    
                                // You *cannot* upgrade yourself.
                                if target_user.email == username {
                                    return err_specific("You cannot upgrade your own account.".to_string()).await
                                }

                                // these two types are not allowed to deactivate other users
                                match authorizer_role {
                                    UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                    UserRole::VIEWER => return err_insufficent_permissions().await,
                                    _=> (),
                                }         
                                                                                        
                                match db_get_user_role(&target_user.email, &db).await { 
                                    Ok(target_user_role) => {
                                        // We cannot upgrade Admins here.  Only when directly accessing the database.
                                        if authorizer_role < target_user_role && target_user_role > UserRole::ADMIN {
                                            //db_upgrade_user(&target_user.email, &db).await;
                                            return worker::Response::ok("User Upgraded");
                                        } else {
                                            return err_insufficent_permissions().await;
                                        }
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,                                
                                }               
                            },
                            Err(_) => return err_bad_request().await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await, 
                }
            } else {
                return err_specific("Header didn't have username the second time?".to_string()).await
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_downgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
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
            }

            if let Ok(username) = header_get_username(&req).await{
                match db_get_user_role(&username, &db).await {                 
                    Ok(authorizer_role) => {

                        match req.json::<EmailSubmission>().await {                                                        
                            Ok(target_user) =>{
                                match db_has_active_user(&target_user.email, &db).await {
                                    Ok(exists) => if !exists {
                                        return err_specific("User does not exist or may be deactivated.".to_string()).await;
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,
                                };
                    
                                // You *cannot* upgrade yourself.
                                if target_user.email == username {
                                    return err_specific("You cannot downgrade your own account.".to_string()).await
                                }

                                // these two types are not allowed to deactivate other users
                                match authorizer_role {
                                    UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                    UserRole::VIEWER => return err_insufficent_permissions().await,
                                    _=> (),
                                }         
                                                                                        
                                match db_get_user_role(&target_user.email, &db).await { 
                                    Ok(target_user_role) => {
                                        // We cannot downgrade viewers.  Deactivating them is a different code path
                                        if authorizer_role < target_user_role && target_user_role < UserRole::VIEWER {
                                            //db_downgrade_user(&target_user.email, &db).await;
                                            return worker::Response::ok("User Upgraded");
                                        } else {
                                            return err_insufficent_permissions().await;
                                        }
                                    },
                                    Err(e) => return err_specific(e.to_string()).await,                                
                                }               
                            },
                            Err(_) => return err_bad_request().await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await, 
                }
            } else {
                return err_specific("Header didn't have username the second time?".to_string()).await
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_add_email(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    if let Some(resp) = header_has_token(&req).await{
        return resp;
    }

    if let Some(resp) = header_has_username(&req).await {
        return resp;
    }

    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            if !header_token_is_valid(&req, &db).await {
                return err_not_logged_in().await
            }

            match header_get_username(&req).await {
                Ok(username) => {
                    match req.json::<EmailSubmission>().await {                                                        
                        Ok (email) => {
                            // db_replace_email
                            // send_email for confirmation
                        },
                        Err(_) => return err_bad_request().await,
                        }

                    
                },
                Err(_) => return err_specific("Header didn't have username the second time?".to_string()).await
            }

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
pub async fn db_has_active_user(email: &String, db: &D1Database) -> worker::Result<bool> {
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

pub async fn db_email_taken(email: &String, db: &D1Database) -> worker::Result<bool> {
    let query = db.prepare("SELECT count(*) AS the_count FROM users WHERE username = ?").bind(&[email.into()]).unwrap();

    match query.first::<BasicCount>(None).await {
        Ok(r) => {
            match r {
                Some(thing) => return Ok(thing.the_count > 0),
                None => return Ok(false),
            }
        },
        Err(e) => return Err(e),
    }    
}

#[derive(Serialize, Deserialize)]
struct Role{
    role: i32,
}

pub async fn db_get_user_role(email: &String, db: &D1Database) -> worker::Result<UserRole> {
    // roles are only meaningful if the user is active.
    let query = db.prepare("SELECT role FROM users WHERE active = 1 AND username = ?").bind(&[email.into()]).unwrap();

    match query.first::<Role>(None).await {
        Ok(r) => {
            match r {
                Some(role) => {
                    match number_to_role(role.role).await{
                        Ok(user_role) => return Ok(user_role),
                        Err(e) => return Err(e),
                    }
                },
                None => Err("Database error! Could not find user despite already being verified!".into()),
            }
        },
        Err(e) => return Err(e),
    }
}

pub async fn db_get_user_details(email: &String, db: &D1Database) -> worker::Result<UserDetails> {
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

pub async fn db_deactivate_user(email: &String, db: &D1Database) {
    let query = db.prepare("UPDATE users SET active = 0 WHERE username = ?").bind(&[email.into()]).unwrap();
    
    match query.first::<UserDetails>(None).await {
        Ok(_) => (),
        Err(e) => panic!("{}", e.to_string()),
    }
}

// SECTION!! generic server tasks
pub async fn  header_has_token(req: &Request) -> Option<worker::Result<Response>> {
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

pub async fn header_has_username(req: &Request) -> Option<worker::Result<Response>> {
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

pub async fn header_get_username(req: &Request) -> worker::Result<String> {
    match req.headers().get("username"){
        Ok(user) => {
            match user {
                Some(username) => return Ok(username),
                None => panic!("No username found under username in header."),
            }
        },
        Err(e) => return Err(e),
    }
}

pub async fn hash_password(username: &String, password: &String) -> worker::Result<String> {
    // Right here we need to do a little bit of server-only stuff!! For safety.  Only on production!
    
    // So this needs some documentation.
    // Basically, we need to conver the string into its u8 array and then into it's u64 array, because that is what randChaCha accepts
    let username_seed: u64;
    unsafe {
        username_seed = username.as_bytes().align_to::<u64>().1[0]; 
    }

    // RandChaCha will provide a repeatable result from the username so that even if the way that cloudflare structures its servers
    // We do not need to worry about the seeds changing.
    // So we generate the salt string using the seeded rng 
    let rng = rand_chacha::ChaCha12Rng::seed_from_u64(username_seed);
    let salt = SaltString::generate(rng);
    
    match Argon2::default().hash_password(password.as_bytes(), &salt) {
        Ok(s) => return Ok(s.to_string()),
        Err(e) => return Err(e.to_string().into()),
    }
}

// this is going to be a big one.  We'll need to 1. Lookup an entry on username/tokens
// 2. Compare the token they gave us and see if it matches the username. 
// 3. See if the token is still valid.
pub async fn header_token_is_valid(_req: &Request, _db: &D1Database) -> bool {
    true
}

pub async fn number_to_role(n: i32) -> worker::Result<UserRole> {
    match n {
        0 => Ok(UserRole::OWNER),
        1 => Ok(UserRole::ADMIN),
        2 => Ok(UserRole::MAINTAINER),
        3 => Ok(UserRole::VIEWER),
        _ => panic!("Tried to convert a number into a UserRole, but the number is out of range: {}.", n)
    }
}

pub async fn send_confirmation_link(address : String) -> worker::Result<worker::Response> {
    if !(EmailAddress::is_valid(&address)){
        return err_specific(format!("Tried to send automated email to invalid email address {}", address)).await
    }

    let to_address: lettre::message::Mailbox = address.parse().unwrap();
    let from_address: lettre::message::Mailbox = "FSO Tables Registration <registration@fsotables.com>".parse().unwrap();

    match Message::builder()
        .to(to_address)
        .from(from_address)
        .subject("Confirm Your FSO Tables Account")
        .body("<h1>TODO!</h1>".to_string())
        {
            Ok(email) => {
                match transport::smtp::SmtpTransport::relay(secrets::SMTP_SERVER) {
                    Ok(relay_bulder) => 
                    {
                        let relay = relay_bulder.credentials(transport::smtp::authentication::Credentials::new(secrets::SMTP_LOGIN.to_string(), secrets::SMTP_PASSWORD.to_string())).build();        
                        match relay.send(&email) {
                            Ok(_) => return Response::ok("Registration Successful!  Please confirm your account!"),
                            Err(e) => return err_specific(e.to_string()).await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await,
                }
            },            
            Err(e) => return err_specific(e.to_string()).await,
        }    
}


// SECTION!! Body/Server Failure Responses
pub async fn err_insufficent_permissions() -> worker::Result<Response> {
    Response::error("This operation is not authorizable via our API at your access level.", 403)    
}

pub async fn err_not_logged_in() -> worker::Result<Response> {
    Response::error("You must be logged in to access this endpoint.", 403)
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
