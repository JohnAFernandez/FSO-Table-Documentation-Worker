use std::io::Read;

use db_fso::db_generic_search_query;
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
use rand::distributions::Alphanumeric;
use wasm_bindgen::JsValue;
use chrono::{Utc, TimeDelta};
mod secrets;
mod db_fso;


const DB_NAME: &str = "fso_table_database";    
const DB_ALLOWED_PASSWORD_CHARACTERS: &str = "[^0-9A-Za-z~!@#$%^&*()_\\-+={\\[}\\]|\\\\:;<,>.?\\/]";// 
const DB_MINIMUM_PASSWORD_LENGTH: usize = 8;


#[derive(Serialize)]
struct FullEmailAddress {
    name: String,
    email: String,
}

impl FullEmailAddress {
    fn create_full_email(name: String, email:String) -> FullEmailAddress {
        FullEmailAddress{ name, email}
    }
}

#[derive(Serialize)]
struct EmailMessage {
    sender: FullEmailAddress, 
    to: Vec<FullEmailAddress>,
    subject: String,
    htmlContent: String, // do not change, as this needs to have this case to be properly processed by Bevo
}

impl EmailMessage {
    fn create_activation_email(email: &String, code: &String) -> EmailMessage{
        EmailMessage{
            sender : FullEmailAddress::create_full_email("FSO Tables Database User Activations".to_string(), "activations@fsotables.com".to_string()),
            to : vec![], 
            subject : "Account Confirmation Link".to_string(),
            htmlContent : format!("<h1 style=\"text-align:center\">Welcome to the Fresspace Open Table Database!</h1><br><br><h3>Please <a href=\"https://fso-tables-worker.johnandrewfernandez12.workers.dev/validation/{}/{}\">confirm your email</a>.</h3>", email, code),
        }
    }
}


//  POST, GET, PATCH, and DELETE -- PUTS AND PATCHES are going to be the same.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context,) -> worker::Result<Response> {
    
    // Table list: Actions, Deprecations, email_validations, fso_items, fso_tables, parse_behaviors, restrictions, sessions, table_aliases, users 
    // Email validations do not need get requests, this is only for the activate user
    // table_aliases, users
    Router::new()
        .get_async("/", root_get)
        .get_async("/users", db_fso::db_user_stats_get)       // No Post, put, patch, or delete for overarching category
        .post_async("/users/register", user_register_new)
        .get_async("/validation/:email/:id", user_confirm_email)
        .get_async("/validation/:email/:id/password", user_confirm_email)
        .get_async("/users/myaccount", user_get_details)
        .post_async("/users/myaccount/password", user_change_password)
        .get_async("/users/login", user_login)
        .post_async("/users/activate", activate_user).put_async("/users/activate", activate_user).patch_async("/users/activate", activate_user)
        .post_async("/users/:username/upgrade", user_upgrade_user_permissions).patch_async("/users/:username/upgrade", user_upgrade_user_permissions)
        .post_async("/users/:username/downgrade", user_downgrade_user_permissions).patch_async("/users/:username/downgrade", user_downgrade_user_permissions)
        .delete_async("/users", deactivate_user)
        .get_async("/tables/parse-types", get_parse_types)
        .get_async("/tables/parse-types/:id", get_parse_type)
        //.post_async("/tables/parse-types", post_parse_behavior)
        .patch_async("/tables/parse-types", update_parse_type).put_async("/tables/parse-types", update_parse_type)
        //.delete_async("/tables/parse-types/:id", delete_parse_type) // Admin only
        .get_async("/tables", get_tables) // tables just need to be done manually on my end, because we don't have many tables *and* it's less effort than just populating.
        .get_async("/tables/items", get_items)
        .get_async("/tables/items/:id", get_item)
        //.post_async("/tables/items", post_item) // Requires login
        .patch_async("/tables/items", update_item).put_async("/tables/items", update_item) //Requires login 
        //.delete_async("/tables/items/:id", delete_item) // Admin only
        .get_async("/tables/aliases", get_aliases)
        .get_async("/tables/aliases/:id", get_alias) 
        //.post_async("/tables/:id/alias", post_alias) // Requires login
        .patch_async("/tables/aliases/:id", update_alias).put_async("/tables/aliases/:id", update_alias) // Requires login
        //.delete_alias("/tables/aliases/:id", delete_alias) // Admin only
        .get_async("/tables/:id", get_table)
        //.get_async("/tables/:id/items", get_tables_items)
        .get_async("/tables/restrictions", get_restrictions)
        .get_async("/tables/restrictions/:id", get_restriction)
        //.post_async("/tables/items/:id/restriction", post_restriction) // Requires login
        .patch_async("/tables/restriction/:id", update_restriction).put_async("/tables/restriction/:id", update_restriction) // Requires login
        //.delete_async("/tables/restrictions/:id", delete_restriction) // Admin only
        .get_async("/tables/deprecations", get_deprecations) 
        .get_async("/tables/deprecations/:id", get_deprecation)
        //.post_async("/tables/deprecations", post_deprecation) // Requires login
        .patch_async("/tables/deprecations", update_deprecation).put_async("/tables/deprecations", update_deprecation) // Requires login
        //.delete_async("/tables/deprecations/:id", delete_deprecation) // Admin only
        //.get_async("/tables/actions/history", get_completed_history) // Requires login
        //.get_async("/tables/actions/history/:id", get_completed_user_history) // Requires login
        //.get_async("/tables/actions/approvals", get_approval_requests) // Requires login
        //.get_async("/tables/actions/approvals/:id", get_approval_requests_user) // Requires login, for seeing just mine, or admin seeing specific other user
        //.get_async("/tables/actions/rejections", get_rejected_requests) // Requires login
        //.get_async("/tables/actions/rejections/:id": get_rejcted_requests_user) // Requires login
        //.post_async("/tables/actions/:id:/approve", approve_request) // Requires login and admin
        //.post_async("/tables/actions/:id:/reject", reject_request) // Requries login and admin
        .post_async("/bugreport", add_bug_report)
        .patch_async("/bugreport/:id/resolve", resolve_bug_report)
        .patch_async("/bugreport/:id/acknowledge", acknowledge_bug_report)
        .patch_async("/bugreport/:id/unresolve", unresolve_bug_report)
        .patch_async("/bugreport/:id/edit", update_bug_report)
        .get_async("/test", test_all) // This might eventually be a "CI" test, but for now it just displays a message.
        .or_else_any_method_async("/", err_api_fallback) // TODO, this does not work.
        .run(req, env)
        .await


        /* // TODO? 
        .route("/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
        */
}

pub async fn test_all(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    
    let mut _return_object = db_fso::FsoTablesQueryResults::new_results().await;

    return Response::ok("Test API is deactivated as tests were successful.");
}

pub async fn root_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    Response::ok("You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors.\n\nThis API is currently under construction!".to_string())
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
            match db_fso::db_email_taken(&email.email, &db1).await {
                Ok(exists) => if exists {
                    return err_specific("User already exists".to_string()).await;
                },
                Err(e) => return err_specific(e.to_string()).await,
            };
            
            let statement = db1.prepare("INSERT INTO users (username, role, active, contribution_count) VALUES (?, 3, 0, 0)").bind(&[email.email.clone().into()]);
            match &statement {
                Ok(q) => {
                    if let Err(e) = q.run().await {
                        return err_specific(e.to_string()).await;
                    }

                },
                Err(e) => return err_specific(e.to_string()).await,
            }

            let mut success = false;
            let mut error_message = "".to_string();
            let activation_string = create_random_string().await;

            match hash_string(&email.email, &activation_string).await {
                Ok(scrambled_string) => {
                    match &db1.prepare(format!("INSERT INTO email_validations (username, secure_key) VALUES (?, \"{}\")", &scrambled_string)).bind(&[email.email.clone().into()]) {
                        Ok(q) => {
                            // if this fails, then we need to delete the inserted row.        
                            if let Err(e) = q.run().await {
                                error_message = e.to_string();
                            } else {
                                success = true;
                            }
        
                        },
                        Err(e) => error_message = e.to_string(),
                    }
                },
                Err(e) =>{ error_message = e.to_string()},
            }
            
            if success{
                return send_confirmation_link(&email.email, &activation_string).await
            } else {
                let statement = db1.prepare("DELETE FROM email_validations WHERE username = ?").bind(&[email.email.clone().into()]);
                match &statement {
                    Ok(q) => {
                        if let Err(e) = q.run().await {
                            return err_specific(e.to_string()).await;
                        }
    
                    },
                    Err(e) => return err_specific(e.to_string()).await,
                }    
                return err_specific(error_message).await;
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }

}

pub async fn user_confirm_email(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id") {
        Some(key) => {
            match ctx.param("email"){
                Some(username) => {
                    let hashed: String;
                    
                    match hash_string(username, key).await {
                        Ok(string) => hashed = string,
                        Err(e) => return err_specific(e.to_string() + " user confirm email new error").await,
                    }

                    match db_generic_search_query(&db_fso::Table::EmailValidations, 2, &username, &hashed, &ctx).await{
                        Ok(result) => {
                            if result.email_validations.is_empty() {
                                return err_specific("Bad credentials, please resubmit. User_confirm_email 1".to_string()).await
                            }                         

                            // double check that we haven't already validated this email.
                            match db_generic_search_query(&db_fso::Table::Users, 2, username, &"".to_string(), &ctx).await {
                                Ok(results) => 
                                if results.users.is_empty() {
                                    return err_specific("No matching user found. User_confirm_email 2".to_string()).await
                                } else if results.users[0].email_confirmed != 0 {
                                    return err_specific("Email is either already confirmed or in error state. Please contact the admin if you cannot access your account. User_confirm_email 3".to_string()).await;
                                },
                                Err(e) => return err_specific(e.to_string() + " User_confirm_email 4").await,
                            }

                            match req.headers().has("password"){
                                Ok(contains)=> { 
                                    if contains {
                                        match req.headers().get("password"){
                                            Ok(option) => {
                                                match option {
                                                    Some(password) => {
                                                        match hash_string(&username, &password).await {
                                                            Ok(hashed_password) => {
                                                                match db_fso::db_set_new_pass(&username, &hashed_password, &ctx).await {
                                                                    Ok(_) => (),
                                                                    Err(e) => return err_specific(e.to_string() + " User_confirm_email 5").await,
                                                                }

                                                                match db_fso::db_generic_delete(db_fso::Table::EmailValidations, &username, &ctx).await {
                                                                    Ok(_) => (),
                                                                    Err(e) => return err_specific(e.to_string() + " User_confirm_email 6").await,
                                                                }

                                                                return create_session_and_send(&username, &ctx).await;   
                                                            },
                                                            Err(e) => err_specific(e.to_string() + "User_confirm_email 7").await,
                                                        }
                                                    },
                                                    None => return err_specific("Password missing from headers".to_string() + "User_confirm_email 8").await,
                                                }
                                            },
                                            Err(e) => return err_specific(e.to_string() + "User_confirm_email 9").await,
                                        }                                        
                                    } else {
                                        match db_fso::db_generic_delete(db_fso::Table::EmailValidations, &username, &ctx).await {
                                            Ok(_) => (),
                                            Err(e) => return err_specific(e.to_string() + " User_confirm_email 15").await,
                                        }

                                        match db_fso::db_set_email_confirmed(&username, &ctx).await {
                                            Ok(_) => return create_session_and_send(&username, &ctx).await,
                                            Err(e) => return err_specific(e.to_string() + "User_confirm_email 10").await,
                                        }

                                    }
                                },
                                Err(_) => return Response::ok("GO AHEAD AND SET THAT THERE PASSWORD SON. User_confirm_email 11"),
                            }
                        },
                        Err(e) => return err_specific(e.to_string()).await,
                    }
                },
                None => return err_specific("Activation failed. Missing username.".to_string() + "User_confirm_email 13").await,
            }
        },
        None => return err_specific("Activation failed.  Missing activation code.".to_string() + "User_confirm_email 14").await,
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
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_details(&username, &db).await {
                Ok(res) => return Response::from_json(&res),
                Err(e) => return err_specific(e.to_string()).await,
            }    
                  
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}


pub async fn deactivate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {    
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_specific(session_result.1).await
            }

            let username = session_result.1;
            
            if !db_fso::db_user_is_active(&username, &db).await {
                return err_user_not_active().await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
                                Ok(exists) => if !exists {
                                    return err_specific("User does not exist or may already be deactivated.".to_string()).await;
                                },
                                Err(e) => return err_specific(e.to_string()).await,
                            };
                
                            // Owners can only be deactivated by someone working directly with the database.
                            // But otherwise, you *can* deactivate yourself.
                            if target_user.email == username && authorizer_role != db_fso::UserRole::OWNER {
                                
                                match db_fso::db_deactivate_user(&username, &db).await {
                                    Ok(_) => return worker::Response::ok("User Deactivated"),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }

                            }

                            // these two types are not allowed to deactivate other users
                            match authorizer_role {
                                db_fso::UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                                _=> (),
                            }         
                                                                                    
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    if authorizer_role < target_user_role{
                                        match db_fso::db_deactivate_user(&target_user.email, &db).await {
                                            Ok(_) => return worker::Response::ok("User Deactivated"),
                                            Err(e) => return err_specific(e.to_string()).await,
                                        }
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
            
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn activate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match req.json::<EmailSubmission>().await {                                                        
                Ok(target_user) =>{
                    match db_fso::db_email_taken(&target_user.email, &db).await {
                        Ok(exists) => if !exists {
                            return err_specific("User to activate does not exist.".to_string()).await;
                        },
                        Err(e) => return err_specific(e.to_string()).await,
                    };

                    // make no changes if this user already exists
                    if db_fso::db_user_is_active(&target_user.email, &db).await {
                        return worker::Response::ok("User is already Active")
                    }

                    // We need to see if the activating user is active, otherwise we should ignore
                    if !db_fso::db_user_is_active(&username, &db).await {
                        // Owners can only be deactivated by someone working directly with the database.
                        // But otherwise, you *can* deactivate yourself.
                        if target_user.email == username{
                            match db_fso::db_activate_user(&target_user.email, &db).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }
                        } else {
                            return err_user_not_active().await
                        }                                
                    }
                    // NOTE! IF WE GET HERE THE USER IS ACTIVE! AND WE NEED TO DEACTIVATE ON EVERY FAILURE!
    
                    match db_fso::db_get_user_role(&username, &db).await {                 
                        Ok(authorizer_role) => {
    
                        // these two types are not allowed to deactivate other users, and the owner can only be activated
                        // directly.
                        match authorizer_role {
                            db_fso::UserRole::OWNER => {
                                let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                return err_insufficent_permissions().await
                            }
                            db_fso::UserRole::MAINTAINER => {
                                if target_user.email != username{
                                    let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                    return err_insufficent_permissions().await    
                                }
                            },
                            db_fso::UserRole::VIEWER => { 
                                if target_user.email != username{
                                    let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                    return err_insufficent_permissions().await
                                }
                            },
                            _=> (),
                        }         
                    
                        // activate the user
                        match db_fso::db_get_user_role(&target_user.email, &db).await {
                            Ok(role) => {
                                // only allow returning accounts to be maintainers in case a bad actor decides to 
                                // try to act via a deactivated Admin
                                if role < db_fso::UserRole::MAINTAINER{
                                    match db_fso::db_force_role(&target_user.email, &db, db_fso::UserRole::MAINTAINER).await {
                                        Ok(_) => return worker::Response::ok("User Activated"),
                                        Err(e) => return err_specific(e.to_string()).await,
                                    }
                                } else {
                                    return worker::Response::ok("User Activated")
                                }
                            },
                            Err(e) => {
                                let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                return err_specific(e.to_string()).await
                            }
                        }
                        },
                        Err(e) => {
                            let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                            return err_specific(e.to_string()).await
                        }
                    }    
                },
                Err(_) => return err_bad_request().await,
            }        
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest{
    email: String,
    password: String,
}


pub async fn user_login(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            match req.json::<LoginRequest>().await{
                Ok(login) => {
                    match db_fso::db_email_taken(&login.email, &db).await {
                        Ok(b) => if !b { return err_specific("User does not exist.".to_string()).await },
                        Err(e) => return err_specific(e.to_string()  + "Part 3").await,
                    }
                    match hash_string(&login.email, &login.password).await {
                        Ok(hash) => {
                            if db_fso::db_check_password(&login.email, &hash, &db).await {
                                return create_session_and_send(&login.email, &ctx).await;
                            } else {
                                return worker::Response::error("Login unsuccessful! Part 4", 403);
                            }
                        },
                        Err(_) => return err_specific("Hashing function failed.".to_string()  + "Part 5").await,
                    }                    
                },
                Err(e) => return err_specific(e.to_string()  + "Part 6").await,
            }
        },
    Err(e) => err_specific(e.to_string()  + "Part 7").await,
    }

}

#[derive(Serialize, Deserialize)]
pub struct Password{
    password: String,
}

pub async fn user_change_password(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {

            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;
            match req.json::<Password>().await{
                Ok(password) => {
                    match check_password_requirements(&password.password).await{
                        Ok(_) => (),
                        Err(e) => return err_specific(e.to_string()).await,
                    }
                    
                    match hash_string(&username, &password.password).await {                             
                        Ok(hash) => { 
                            match db_fso::db_set_new_pass(&username, &hash, &ctx).await {
                                Ok(_) => return worker::Response::ok("Password Changed!"),
                                Err(e) => return err_specific(e.to_string()).await,
                            }
                        },
                        Err(e) => return err_specific(e.to_string() + &" Hashing function failed.".to_string()).await,
                    }                            
                },
                Err(_) => return err_bad_request().await,
            }
        },
        Err(e)=> err_specific(e.to_string()).await,
    }
}

pub async fn check_password_requirements(password: &String) -> Result<()> {
    if password.len() < DB_MINIMUM_PASSWORD_LENGTH {
        return Err("Password is too short, please submit a new password".to_string().into())
    }

    match Regex::new(DB_ALLOWED_PASSWORD_CHARACTERS) {
        Ok(search_set) => {
            match search_set.find(&password) {
                Some(_) => return Err("Disallowed password characters found, please submit a new password.".to_string().into()),
                None => return Ok(()),
            }    
        },
        Err(e) => return Err(e.to_string().into())
    }
}

pub async fn user_upgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {    
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            if !db_fso::db_user_is_active(&username, &db).await {
                return err_user_not_active().await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
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
                                db_fso::UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                                _=> (),
                            }         

                            // TODO! Extra check needed?                                                                                        
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    // We cannot upgrade Admins here.  Only when directly accessing the database.
                                    if authorizer_role < target_user_role && target_user_role > db_fso::UserRole::ADMIN {
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
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn user_downgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            if !db_fso::db_user_is_active(&username, &db).await {
                return err_user_not_active().await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
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
                                db_fso::UserRole::MAINTAINER => return err_insufficent_permissions().await,
                                db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                                _=> (),
                            }         

                            // TODO! Do we need extra checks here?                                                                                        
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    // We cannot downgrade viewers.  Deactivating them is a different code path
                                    if authorizer_role < target_user_role && target_user_role < db_fso::UserRole::VIEWER {
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
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_parse_types(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::ParseBehaviors, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(results) => return Response::from_json(&results.parse_behaviors),
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_parse_type(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::ParseBehaviors, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.parse_behaviors),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}


pub async fn update_parse_type(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match req.json::<db_fso::ParseBehavior>().await {
                        Ok(parse_behavior) => {
                            if parse_behavior.behavior_id < 0 {
                                return err_specific("Invalid behavior id, cannot update.".to_string()).await;
                            }

                            if parse_behavior.behavior != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::ParseBehaviors, 0, &parse_behavior.behavior, &parse_behavior.behavior_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }    
                            }

                            if parse_behavior.description != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::ParseBehaviors, 1, &parse_behavior.description, &parse_behavior.behavior_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has a behavior_id, behavior, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.").await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_items(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::FsoItems, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Response::from_json(&result.fso_items);
        },
        Err(e) => {
            return err_specific(e.to_string()).await;
        }
    }
}

pub async fn get_item(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::FsoItems, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.fso_items),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}

pub async fn update_item(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match req.json::<db_fso::FsoItems>().await {
                        Ok(item) => {
                            if item.item_id < 0 {
                                return err_specific("Invalid item id, cannot update.".to_string()).await;
                            }

                            if item.default_value != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 0, &item.default_value, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }    
                            }

                            if item.deprecation_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 1, &item.deprecation_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.documentation != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 2, &item.documentation, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.info_type != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 3, &item.info_type, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.item_text != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 4, &item.item_text, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.major_version != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 5, &item.major_version, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }
                            
                            if item.parent_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 6, &item.parent_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.restriction_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 7, &item.restriction_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            if item.table_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 8, &item.table_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has an item_id, behavior, and description, even if not updating.  If not updating a field (id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or more negative number for ids for no update.  Echo back other values for no update.").await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_tables(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::FsoTables, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Response::from_json(&result.fso_tables);
        },
        Err(e) => {
            return err_specific(e.to_string()).await;
        }
    }
}

pub async fn get_table(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::FsoTables, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.fso_tables),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}

pub async fn get_aliases(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::TableAliases, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Response::from_json(&result.table_aliases);
        },
        Err(e) => {
            return err_specific(e.to_string()).await;
        }
    }
}

pub async fn get_alias(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::TableAliases, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.table_aliases),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}

pub async fn update_alias(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match req.json::<db_fso::TableAlias>().await {
                        Ok(table_alias) => {
                            if table_alias.alias_id < 0 {
                                return err_specific("Invalid table alias id, cannot update.".to_string()).await;
                            }

                            if table_alias.filename != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::TableAliases, 0, &table_alias.filename, &table_alias.alias_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }    
                            }

                            if table_alias.table_id > -2{
                                match db_fso::db_generic_update_query(&db_fso::Table::TableAliases, 1, &table_alias.table_id.to_string(), &table_alias.alias_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has an alias_id, filename, and table_id, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.").await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_restrictions(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::Restrictions, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Response::from_json(&result.restrictions);
        },
        Err(e) => {
            return err_specific(e.to_string()).await;
        }
    }
}

pub async fn get_restriction(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::Restrictions, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.restrictions),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}

pub async fn update_restriction(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match req.json::<db_fso::Restrictions>().await {
                        Ok(restriction) => {
                            if restriction.restriction_id < 0 {
                                return err_specific("Invalid restriction id, cannot update.".to_string()).await;
                            }

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 0, &restriction.illegal_value_float.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }    

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 1, &restriction.illegal_value_int.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }
                            
                            if restriction.max_string_length > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 2, &restriction.max_string_length.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }    
                            }

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 3, &restriction.max_value.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }    

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 4, &restriction.min_value.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }    

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has a restriction_id, illegal_value_float, illegal_value_int, max_string_length, max_value, min_value, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.").await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn get_deprecations(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::Deprecations, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Response::from_json(&result.deprecations);
        },
        Err(e) => {
            return err_specific(e.to_string()).await;
        }
    }
}

pub async fn get_deprecation(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::Deprecations, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Response::from_json(&results.deprecations),
            Err(e) => return err_specific(e.to_string()).await,
        },
        None => return err_specific("Internal Server Error, route parameter mismatch!".to_string()).await,
    }
}

pub async fn update_deprecation(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match req.json::<db_fso::Deprecations>().await {
                        Ok(deprecation) => {
                            if deprecation.deprecation_id < 0 {
                                return err_specific("Invalid deprecation id, cannot update.".to_string()).await;
                            }

                            if deprecation.date != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::Deprecations, 0, &deprecation.date, &deprecation.deprecation_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }    
                            }

                            if deprecation.version != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::Deprecations, 1, &deprecation.version, &deprecation.deprecation_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific(e.to_string()).await,
                                }
                            }

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has a deprecation_id, date, and version, even if not updating.  If not updating a field (deprecation_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.").await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

#[derive(Serialize, Deserialize)]
pub struct BugReport{
    user_id: i32,
    bug_type : String,
    description: String,
}


pub async fn add_bug_report(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;

            match req.json::<BugReport>().await{
                Ok(report) =>{
                    if report.description.is_empty() {
                        return err_specific("Please provide a description when submitting a bug report.".to_string()).await
                    }

                    let mut username = "Anonymous User".to_string();
                    if session_result.0 {
                        username = session_result.1;
                    }

                    match db_fso::db_insert_bug_report(&username, &report.bug_type, &report.description, &ctx).await {
                        Ok(_) => Response::ok("Success!"),
                        Err(e) => err_specific(e.to_string()).await,
                    }
        
                }, 
                Err(e) => err_specific(e.to_string()).await,




            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }
}

pub async fn resolve_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        db_fso::UserRole::MAINTAINER => return err_insufficent_permissions().await,
                        _=> (),
                    }         
                    match ctx.param("id"){
                        Some(id) => {
                            match id.parse::<i32>(){
                                Ok(parsed_id) =>{
                                    if parsed_id < 0 {
                                        return err_specific("Invalid bug report id, cannot update.".to_string()).await;
                                    }

                                    match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"3".to_string(), &id,  &ctx).await {
                                        Ok(_) => (),
                                        Err(e) => return err_specific(e.to_string()).await,
                                    }
                                
                                    return Response::ok("Success!")
                                }
                                Err(_) => return err_specific("Bug report id cannot be parsed as an integer, please resubmit your request.".to_string()).await,
                            }
                        },
                        None => return err_specific("Please submit an id in the url as part of the request to acknowledge a bug report.".to_string()).await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }
        }
        Err(e) => return err_specific(e.to_string()).await,
    }
}


pub async fn unresolve_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return err_insufficent_permissions().await,
                        db_fso::UserRole::MAINTAINER => return err_insufficent_permissions().await,
                        _=> (),
                    }         

                    match ctx.param("id"){
                        Some(id) => {
                            match id.parse::<i32>(){
                                Ok(parsed_id) =>{
                                    if parsed_id < 0 {
                                            return err_specific("Invalid bug report id, cannot update.".to_string()).await;
                                    }

                                    match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"0".to_string(), &id.to_string(),  &ctx).await {
                                        Ok(_) => (),
                                        Err(e) => return err_specific(e.to_string()).await,
                                    }

                                    return Response::ok("Success!")
                                },

                                Err(_) => return err_specific("Bug report id cannot be parsed as an integer, please resubmit your request.".to_string()).await,
                            }
                        }
                        None => return err_specific("Please submit an id in the url as part of the request to acknowledge a bug report.".to_string()).await,
                    }
                },
                Err(e) => return err_specific(e.to_string()).await,
            }
        }
        Err(e) => return err_specific(e.to_string()).await,
    }
}


pub async fn acknowledge_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::OWNER => (),
                        db_fso::UserRole::ADMIN => (),
                        _=> return err_specific("Only administrators can acknowledge bug reports".to_string()).await,
                    }         
                },
                Err(e) => return err_specific(e.to_string()).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(parsed_id) =>{
                            if parsed_id < 0 {
                                return err_specific("Invalid bug report id, cannot update.".to_string()).await;
                            }
        
                            match db_fso::db_generic_search_query(&db_fso::Table::BugReports, 0, &id, &"".to_string(), &ctx).await {
                                Ok(bug_report_result) => {
                                    if bug_report_result.bug_reports.is_empty() {
                                        return err_specific("Could not find a matching bug report.".to_string()).await;
                                    }
        
                                },
                                Err(e) => return err_specific(e.to_string()).await,
                            }
        
                            match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"1".to_string(), &id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific(e.to_string()).await,
                            }
        
                            return Response::ok("Success!")
                        },
                        Err(_) => return err_specific("Bug report id cannot be parsed as an integer, please resubmit your request.".to_string()).await,
                    }
                    
                },

                None => return err_specific("Please submit an id in the url as part of the request to acknowledge a bug report.".to_string()).await,
            }

        }
        Err(e) => return err_specific(e.to_string()).await,
    }
}



#[derive(Serialize, Deserialize)]
pub struct BugReportInfo{
    bug_type : String,
    description: String,
}

pub async fn update_bug_report(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db).await;
            if !session_result.0 {
                return err_not_logged_in().await
            }

            let username = session_result.1;
            let mut administrator = false;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::OWNER => administrator = true,
                        db_fso::UserRole::ADMIN => administrator = true,
                        _=> (),
                    }         
                },                
                Err(e) => return err_specific(e.to_string()).await,
            }

            let bug_id: i32; 

            // MAJOR TODO!!! getting the id from the URL, we have not been checking that the id is numeric, so we need to go back and verify those are correct.
            // Here is an example of it done correctly, below.
            match ctx.param("id"){
                Some(id) => { 
                    match id.parse::<i32>() {
                        Ok(parsed) => bug_id = parsed,
                        Err(_) => return err_specific("Cannot parse the supplied bug report id.".to_string()).await,
                    }
                },
                None => return err_specific("Invalid bug report id, cannot update.".to_string()).await,
            }

            if !administrator {
                match db_fso::db_generic_search_query(&db_fso::Table::Users, 2, &username, &"".to_string(), &ctx).await {
                    Ok(user_result) => {
                        if user_result.users.is_empty(){
                            return err_specific("Could not find a matching user for the username logged in somehow. You should probably submit a new bug report.".to_string()).await
                        }

                        match db_fso::db_generic_search_query(&db_fso::Table::BugReports, 1, &bug_id.to_string(), &"".to_string(), &ctx).await {
                            Ok(bug_report_result) => {
                                if user_result.users[0].id != bug_report_result.bug_reports[0].user_id {
                                    return err_specific("Only the reporter of a bug or an administrator can edit the contents of a bug report.".to_string()).await
                                }
                            }
                            Err(e) => return err_specific(e.to_string()).await,
                        }
                    },
                    Err(e) => return err_specific(e.to_string()).await,
                }
            }



            match req.json::<BugReportInfo>().await {
                Ok(bug_info) => {
                    if bug_info.bug_type != "~!!NO UPDATE!!~"{
                        match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 1, &bug_info.bug_type, &bug_id.to_string(),  &ctx).await {
                            Ok(_) => (),
                            Err(e) => return err_specific(e.to_string()).await,
                        }    
                    }

                    if bug_info.description != "~!!NO UPDATE!!~"{
                        match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 2, &bug_info.description, &bug_id.to_string(),  &ctx).await {
                            Ok(_) => (),
                            Err(e) => return err_specific(e.to_string()).await,
                        }
                    }

                    return Response::ok("Success!")

                },
                Err(e) => return err_specific(e.to_string() + "\nMake sure that the request json has an bug_type, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.").await,
            }

        },
        Err(e) => return err_specific(e.to_string()).await,
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
                None => return Err("No username found under username in header.".to_string().into()),
            }
        },
        Err(e) => return Err(e),
    }
}

pub async fn header_get_token(req: &Request) -> worker::Result<String> {
    match req.headers().get("ganymede_token"){
        Ok(token_option) => {
            match token_option {
                Some(token) => return Ok(token),
                None => return Err("No token found in header.".to_string().into()),
            }
        },
        Err(e) => return Err(e),
    }
}

pub async fn create_session_and_send(email: &String, ctx: &RouteContext<()>) -> worker::Result<Response> {
    let login_token = create_random_string().await;
    let hashed_string: String;                                

    match hash_string(&email, &login_token).await {
        Ok(hashed) => hashed_string = hashed,
        Err(e) => return err_specific(e.to_string() + " at create_session, 1").await,
    }

    // We give the user two hours to do what they need to do.
    match db_fso::db_session_add(&hashed_string, &email, &(Utc::now() + TimeDelta::hours(2)).to_string(), ctx).await {
        Ok(_) => return worker::Response::ok(format!("{{\"token\":\"{}\"}}", login_token)),
        Err(e) => return err_specific(e.to_string() + " at create_session, 2").await,
    }
}

pub async fn hash_string(username: &String, string: &String) -> worker::Result<String> {
    // Right here we need to do a little bit of server-only stuff!! For safety.  Only on production!

    // So this needs some documentation.
    // Basically, we need to convert the string into its u8 array and then into it's u64 array, because that is what randChaCha accepts
    let bytes = username.as_bytes();
    
    if bytes.is_empty() {
        return Err("Empty username, cannot login.".to_string().into());
    }

    let mut counter = 0;
    let mut username_seed: u64 = 0;

    for byte in bytes.bytes() {
        username_seed *= 256; 
        match byte{
            Ok(b) => username_seed += b as u64,
            Err(_) => (),
        }

        counter += 1;
        if counter > 2{
            break;
        }     
    }

    // RandChaCha will provide a repeatable result from the username so that even if the way that cloudflare structures its servers
    // We do not need to worry about the seeds changing.
    // So we generate the salt string using the seeded rng 
    let rng = rand_chacha::ChaCha12Rng::seed_from_u64(username_seed);
    let salt = SaltString::generate(rng);
    
    match Argon2::default().hash_password(string.as_bytes(), &salt) {
        Ok(s) => match s.hash {

            Some(hash) => {
                return Ok(hash.to_string())
            },
            None => {
                return Err("Hashing function gave an empty output!!".to_string().into())
            },
        },
        Err(e) => return Err(e.to_string().into()),
    }
}

pub async fn create_random_string() -> String {    
    return rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(64)
    .map(char::from)
    .collect();
}

// this is going to be a big one.  We'll need to 1. Lookup an entry on username/tokens
// 2. Compare the token they gave us and see if it matches the username. 
// 3. See if the token is still valid.
pub async fn header_session_is_valid(req: &Request, db: &D1Database) -> (bool, String)  {
    let mut return_tuple = (false, "".to_string());
    
    match header_has_token(&req).await {
        Some(r) => { 
            match r {
                Ok(mut text) => return_tuple.1 = text.text().await.unwrap(),
                Err(e) => return_tuple.1 = e.to_string(),
            }

            return return_tuple;
        },
        None => (),
    }

    match header_has_username(&req).await {
        Some(r) => { 
            match r {
                Ok(mut text) => return_tuple.1 = text.text().await.unwrap(),
                Err(e) => return_tuple.1 = e.to_string(),
            }

            return return_tuple;
        },
        None => (),
    }

    match header_get_token(&req).await{
        Ok(token) => {            
            if let Ok(username) = header_get_username(&req).await{
                return_tuple.1 = username;
            } else {
                return return_tuple;
            }
            
            let hashed_token = hash_string(&return_tuple.1, &token).await.unwrap();

            match db_fso::db_check_token(&return_tuple.1, &hashed_token, Utc::now().to_string(), &db).await {
                Ok(result) => return_tuple.0 = result,
                Err(e) => return_tuple.1 = e.to_string(),
            }

            return return_tuple
        },
        Err(e) => return_tuple.1 = e.to_string(),     
    }    
    
    return return_tuple
}

pub async fn send_confirmation_link(address : &String, activation_key : &String) -> worker::Result<worker::Response> {
    if !(EmailAddress::is_valid(&address)){
        return err_specific(format!("Tried to send automated email to invalid email address {}", address)).await
    }

    let mut headers : Headers = Headers::new();
    match headers.append("content-type", "application/json"){
        Ok(_) => (),
        Err(e) => return err_specific(e.to_string()).await,
    }

    match headers.append("accept", "application/json") {
        Ok(_) => (),
        Err(e) => return err_specific(e.to_string()).await,
    }

    match headers.append("api-key", secrets::SMTP_API_KEY) {
        Ok(_) => (),
        Err(e) => return err_specific(e.to_string()).await,
    }

    let mut message: EmailMessage = EmailMessage::create_activation_email(address, activation_key);
    message.to.push(FullEmailAddress::create_full_email("User".to_string(), address.to_string()));

    let jvalue_out : JsValue;

    match serde_json::to_string(&message) {
        Ok(json_message) => jvalue_out = JsValue::from_str(&json_message),
        Err(e) => return err_specific(e.to_string()).await,
    }

    let mut outbound_request = RequestInit::new();
    outbound_request.with_method(Method::Post).with_headers(headers).with_body(Some(jvalue_out));
    
    let imminent_request = worker::Request::new_with_init("https://api.brevo.com/v3/smtp/email", &outbound_request).unwrap();
    
    match worker::Fetch::Request(imminent_request).send().await {
        Ok(mut res) => { 
            match res.text().await {
                Ok(text) => return Response::ok(text + "Email sent!"),
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
    Response::error("You must be logged and provide an access token to access this endpoint.", 403)
}

pub async fn err_user_not_active() -> worker::Result<Response> {
    Response::error("The user must be active before it can authorize this type of action", 403)
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
