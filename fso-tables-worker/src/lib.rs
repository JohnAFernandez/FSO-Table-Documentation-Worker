use std::{io::Read};

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
use chrono::{Utc, TimeDelta, DateTime};
mod secrets;
mod db_fso;


const DB_NAME: &str = "fso_table_database";    
const DB_ALLOWED_PASSWORD_CHARACTERS: &str = "[^0-9A-Za-z~!@#$%^&*()_\\-+={\\[}\\]|\\\\:;<,>.?\\/]";// 
const DB_MINIMUM_PASSWORD_LENGTH: usize = 10;
const DB_SEMVER_CHARACTERS: &str = "[^0-9.]";

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
    fn create_activation_email(code: &String) -> EmailMessage{
        EmailMessage{
            sender : FullEmailAddress::create_full_email("FSO Tables Database User Activations".to_string(), "activations@fsotables.com".to_string()),
            to : vec![], 
            subject : "Account Confirmation Code".to_string(),
            htmlContent : format!("<div style=\"text-align:center; font-family: calibri; padding: 50px; background-color: #242424; color: #cecece; margin-left:50px; margin-right:50px; border-radius: 5px;\"><h2 style=\"display:flex; justify-content: center;\">Welcome to Ganymede, the Freespace Open Table Option Database</h2> <h3>To activate your account enter this confirmation code at the ganymede website</h3><div style=\"display:flex; justify-content: center;\"><h1 style=\"background-color: #333333; border-radius: 5px; padding:10px; padding-left:15px; padding-right:15px;\">{}</h1></div><br>Account confirmation codes expire in 24 hours.<br><br>If you are unsure why you got this email, please permanently it.</h2></div>", code),
        }
    }

    fn create_password_reset_email(code: &String) -> EmailMessage{
        EmailMessage{
            sender : FullEmailAddress::create_full_email("FSO Tables Database Password Reset".to_string(), "credential.helper@fsotables.com".to_string()),
            to : vec![], 
            subject : "Account Reset Code".to_string(),
            htmlContent : format!("<div style=\"text-align:center; font-family: calibri; padding: 50px; background-color: #242424; color: #cecece; margin-left:50px; margin-right:50px; border-radius: 5px;\"><h2 style=\"display:flex; justify-content: center;\">We received a password reset request for your Ganymede account.<br>Here is your confirmation code:</h2><div style=\"display:flex; justify-content: center;\"><h1 style=\"background-color: #333333; border-radius: 5px; padding:10px; padding-left:15px; padding-right:15px;\">{}</h1></div><br>Confirmation codes expire in 30 minutes.<br><br>If you are unsure why you got this code, please permanently delete this email.</h2></div>", code),
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
        .get_async("/api/", root_get)
        .options_async("/api/", send_cors)        
        // No Post, put, patch, or delete for overarching category
        .get_async("/api/users", db_fso::db_user_stats_get)
        .options_async("/api/users", send_cors)
        .post_async("/api/users/register", user_register_new)
        .options_async("/api/users/register", send_cors)
        .post_async("/api/validation/:email", user_confirm_email)
        .options_async("/api/validation/:email/:id", send_cors)
        .get_async("/api/validation/:email/:id/password", user_confirm_email)
        .options_async("/api/validation/:email/:id/password", send_cors)
        .get_async("/api/users/myaccount", user_get_details)
        .options_async("/api/users/myaccount", send_cors)
        .post_async("/api/users/myaccount/password", user_change_password)
        .options_async("/api/users/myaccount/password", send_cors)
        .post_async("/api/users/reset-password", user_reset_password)
        .options_async("/api/users/reset-password", send_cors)
        .post_async("/api/users/reset-password/confirm", user_reset_password_confirmed)
        .options_async("/api/users/reset-password/confirm", send_cors)
        .post_async("/api/users/login", user_login)
        .options_async("/api/users/login", send_cors)
        .post_async("/api/users/activate", activate_user).put_async("/api/users/activate", activate_user).patch_async("/api/users/activate", activate_user)
        .options_async("/api/users/activate", send_cors)
        .post_async("/api/users/:username/upgrade", user_upgrade_user_permissions).patch_async("/api/users/:username/upgrade", user_upgrade_user_permissions)
        .options_async("/api/users/:username/upgrade", send_cors)
        .post_async("/api/users/:username/downgrade", user_downgrade_user_permissions).patch_async("/api/users/:username/downgrade", user_downgrade_user_permissions)
        .options_async("/api/users/:username/downgrade", send_cors)
        .delete_async("/api/users", deactivate_user)
        .get_async("/api/tables/parse-types", get_parse_types)
        .options_async("/api/tables/parse-types", send_cors)
        .get_async("/api/tables/parse-types/:id", get_parse_type)
        .options_async("/api/tables/parse-types/:id", send_cors)
        //.post_async("/api/tables/parse-types", post_parse_behavior)
        .patch_async("/api/tables/parse-types", update_parse_type).put_async("/api/tables/parse-types", update_parse_type)
        .delete_async("/api/tables/parse-types/:id", delete_parse_type) // Admin only
        // tables just need to be done manually on my end, because we don't have many tables *and* it's less effort than just populating.
        .get_async("/api/tables", get_tables).options_async("/api/tables", send_cors)
        .get_async("/api/tables/items", get_items).options_async("/api/tables/items", send_cors)
        .get_async("/api/tables/items/:id", get_item)
        .options_async("/api/tables/items/:id", send_cors)
        //.post_async("/api/tables/items", post_item) // Requires login
        .patch_async("/api/tables/items", update_item).put_async("/api/tables/items", update_item) //Requires login 
        .delete_async("/api/tables/items/:id", delete_item) // Admin only
        .get_async("/api/tables/aliases", get_aliases).options_async("/api/tables/aliases", send_cors)
        .get_async("/api/tables/aliases/:id", get_alias).options_async("/api/tables/aliases/:id", send_cors)
        //.post_async("/api/tables/:id/alias", post_alias) // Requires login
        .patch_async("/api/tables/aliases/:id", update_alias).put_async("/api/tables/aliases/:id", update_alias) // Requires login
        .delete_async("/api/tables/aliases/:id", delete_alias) // Admin only
        .get_async("/api/tables/:id", get_table).options_async("/api/tables/:id", send_cors)
        //.get_async("/api/tables/:id/items", get_tables_items)
        .get_async("/api/tables/restrictions", get_restrictions).options_async("/api/tables/restrictions", send_cors)
        .get_async("/api/tables/restrictions/:id", get_restriction).options_async("/api/tables/restrictions/:id", send_cors)
        //.post_async("/api/tables/items/:id/restriction", post_restriction) // Requires login
        .patch_async("/api/tables/restriction/:id", update_restriction).put_async("/api/tables/restriction/:id", update_restriction) // Requires login
        .delete_async("/api/tables/restrictions/:id", delete_restriction) // Admin only
        .get_async("/api/tables/deprecations", get_deprecations).options_async("/api/tables/deprecations", send_cors)
        .get_async("/api/tables/deprecations/:id", get_deprecation).options_async("/api/tables/deprecations/:id", send_cors)
        //.post_async("/api/tables/deprecations", post_deprecation) // Requires login
        .patch_async("/api/tables/deprecations", update_deprecation).put_async("/api/tables/deprecations", update_deprecation) // Requires login
        .delete_async("/api/tables/deprecations/:id", delete_deprecation) // Admin only
        //.get_async("/api/tables/actions/history", get_completed_history) // Requires login
        //.get_async("/api/tables/actions/history/:id", get_completed_user_history) // Requires login
        //.get_async("/api/tables/actions/approvals", get_approval_requests) // Requires login
        //.get_async("/api/tables/actions/approvals/:id", get_approval_requests_user) // Requires login, for seeing just mine, or admin seeing specific other user
        //.get_async("/api/tables/actions/rejections", get_rejected_requests) // Requires login
        //.get_async("/api/tables/actions/rejections/:id": get_rejcted_requests_user) // Requires login
        //.post_async("/api/tables/actions/:id:/approve", approve_request) // Requires login and admin
        //.post_async("/api/tables/actions/:id:/reject", reject_request) // Requries login and admin
        .post_async("/api/bugreport", add_bug_report).options_async("/api/bugreport", send_cors)
        .patch_async("/api/bugreport/:id/resolve", resolve_bug_report).options_async("/api/bugreport/:id/resolve", send_cors)
        .patch_async("/api/bugreport/:id/acknowledge", acknowledge_bug_report).options_async("/api/bugreport/:id/acknowledge", send_cors)
        .patch_async("/api/bugreport/:id/unresolve", unresolve_bug_report).options_async("/api/bugreport/:id/unresolve", send_cors)
        .patch_async("/api/bugreport/:id/edit", update_bug_report).options_async("/api/bugreport/:id/edit", send_cors)
        .get_async("/api/test", test_all) // This might eventually be a "CI" test, but for now it just displays a message.
        .or_else_any_method_async("/api/", send_cors) // TODO, this does not work.
        .run(req, env)
        .await


        /* // TODO? 
        .route("/api/users/:username/email", post(add_email).put(add_email).patch(add_email).delete(api_insufficent_permissions))
        */
}

pub async fn test_all(_req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    
    let mut _return_object = db_fso::FsoTablesQueryResults::new_results().await;

    return send_success(&"Test API is deactivated as tests were successful.".to_string(), &"".to_string()).await;
}

pub async fn root_get(_req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
    send_success(&"You have accessed the Freespace Open Table Option Databse API.\n\nRoutes are users, tables, items, deprecations, and behaviors.\n\nThis API is currently under construction!".to_string(), &"".to_string()).await
}

#[derive(Serialize, Deserialize)]
struct EmailSubmission{
    email: String,
}

// TODO! This function should really able to distinguish and report whether the user simply *exists* in the user database or is active. 
pub async fn user_register_new(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    let submission = req.json::<EmailSubmission>().await;
    if submission.is_err() {
        return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await;
    }
    
    let email = submission.unwrap();

    if !EmailAddress::is_valid(&email.email){
        return send_success(&"Email address is not in the right format".to_string(), &"".to_string()).await;
    }

    let db = ctx.env.d1(DB_NAME);
    match &db{
        Ok(db1) => {
            match db_fso::db_user_able_to_register(&email.email, &db1).await {
                Ok(exists) => if !exists {
                    return err_specific("{\"Error\":\"User already exists\"}".to_string()).await;
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00001\"}".to_string(),&(e.to_string() + " | IEC00001"), 500, &ctx).await,
            };
            
            let salt = create_random_string().await;

            let statement = db1.prepare("INSERT INTO users (username, role, active, contribution_count, password2) VALUES (?1, 3, 0, 0, ?2)").bind(&[JsValue::from(&email.email), JsValue::from(&salt)]);
            match &statement {
                Ok(q) => {
                    if let Err(e) = q.run().await {
                        return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00002\"}".to_string(),&(e.to_string() + " | IEC00002"), 500, &ctx).await;
                    }

                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00003\"}".to_string(),&(e.to_string() + " | IEC00003"), 500, &ctx).await,
            }

            let mut success = false;
            let mut error_message = "".to_string();

            // set up a small random string of numbers to send in the email as a confirmation code
            let activation_string = create_random_code().await;

            match hash_string(&salt, &activation_string).await {
                Ok(scrambled_string) => {
                    match  db1.prepare("DELETE FROM email_validations WHERE username = ?").bind(&[JsValue::from(&email.email)]) {
                        Ok(q) => {
                            if let Err(e) = q.run().await {
                                return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00155\"}".to_string(),&(e.to_string() + " | IEC00155"), 500, &ctx).await;
                            }
        
                        },
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00156\"}".to_string(),&(e.to_string() + " | IEC00156"), 500, &ctx).await,
                    }    
                    
                    let mut time =  Utc::now();
                    time = time + TimeDelta::minutes(30);

                    match &db1.prepare(format!("INSERT INTO email_validations (username, secure_key, expires) VALUES (?, \"{}\", \"{}\")", &scrambled_string, time.to_string())).bind(&[JsValue::from(&email.email)]) {
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
                return send_confirmation_email(&email.email, &activation_string.to_string(), &ctx).await
            } else {
                let statement = db1.prepare("DELETE FROM email_validations WHERE username = ?").bind(&[JsValue::from(&email.email)]);
                match &statement {
                    Ok(q) => {
                        if let Err(e) = q.run().await {
                            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00004\"}".to_string(),&(e.to_string() + " | IEC00004"), 500, &ctx).await;
                        }
    
                    },
                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00005\"}".to_string(),&(e.to_string() + " | IEC00005"), 500, &ctx).await,
                }    
                return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00006\"}".to_string(),&(error_message + " | IEC00006"), 500, &ctx).await;
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00007\"}".to_string(),&(e.to_string() + " | IEC00007"), 500, &ctx).await,
    }

}

#[derive(Serialize, Deserialize)]
struct ConfirmationCodeSubmission{
    code: String,
}

pub async fn user_confirm_email(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match req.json::<ConfirmationCodeSubmission>().await {
        Ok(key) => {
            match ctx.param("email"){
                Some(username) => {
                    let hashed: String;
                    let salt_result = db_fso::db_get_user_salt(username, &ctx).await;

                    if salt_result.is_err() {
                        return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00138\"}".to_string(), &(salt_result.unwrap_err().to_string() + " | IEC00138").to_string(), 500, &ctx).await;
                    }

                    let salt = salt_result.unwrap();

                    match hash_string(&salt, &key.code).await {
                        Ok(string) => hashed = string,
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00008\"}".to_string(),&(e.to_string() + " | IEC00008"), 500, &ctx).await,
                    }

                    match db_generic_search_query(&db_fso::Table::EmailValidations, 2, &username, &hashed, &ctx).await{
                        Ok(result) => {
                            if result.email_validations.is_empty() {
                                return err_specific("{\"Error\":\"Bad credentials, please resubmit.\"}".to_string()).await
                            }                         

                            // double check that we haven't already validated this email.
                            match db_generic_search_query(&db_fso::Table::Users, 2, username, &"".to_string(), &ctx).await {
                                Ok(results) => 
                                if results.users.is_empty() {
                                    return err_specific("{\"Error\":\"No matching user found.\"}".to_string()).await
                                } else if results.users[0].email_confirmed != 0 {
                                    return err_specific("{\"Error\":\"Email is either already confirmed or in error state. Please contact the admin if you cannot access your account.\"}".to_string()).await;
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00009\"}".to_string(),&(e.to_string() + " | IEC00009"), 500, &ctx).await,
                            }

                            match result.email_validations[0].expires.parse::<DateTime<chrono::Utc>>(){
                                Ok(expiration_time) => {
                                    if Utc::now() > expiration_time{
                                        return err_specific("{\"Error\":\"Activation link has expired.\"}".to_string()).await;
                                    }
                                }
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00157\"}".to_string(),&(e.to_string() + " | IEC00157"), 500, &ctx).await,
                            }

                            match req.headers().has("password"){
                                Ok(contains)=> { 
                                    if contains {
                                        match req.headers().get("password"){
                                            Ok(option) => {
                                                match option {
                                                    Some(password) => {
                                                        match hash_string(&salt, &password).await {
                                                            Ok(hashed_password) => {
                                                                match db_fso::db_set_new_pass(&username, &hashed_password, &ctx).await {
                                                                    Ok(_) => (),
                                                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00010\"}".to_string(),&(e.to_string() + " | IEC00010"), 500, &ctx).await,
                                                                }

                                                                match db_fso::db_generic_delete(db_fso::Table::EmailValidations, &username, &ctx).await {
                                                                    Ok(_) => (),
                                                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00011\"}".to_string(),&(e.to_string() + " | IEC00011"), 500, &ctx).await,
                                                                }

                                                                return create_session_and_send(&username, &salt, &ctx).await;   
                                                            },
                                                            Err(e) => err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00012\"}".to_string(),&(e.to_string() + " | IEC00012"), 500, &ctx).await,
                                                        }
                                                    },
                                                    None => return err_specific("{\"Error\":\"Password missing from headers\"}".to_string()).await,
                                                }
                                            },
                                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00013\"}".to_string(),&(e.to_string() + " | IEC00013"), 500, &ctx).await,
                                        }                                        
                                    } else {
                                        match db_fso::db_generic_delete(db_fso::Table::EmailValidations, &username, &ctx).await {
                                            Ok(_) => (),
                                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00014\"}".to_string(),&(e.to_string() + " | IEC00014"), 500, &ctx).await,
                                        }

                                        match db_fso::db_set_email_confirmed(&username, &ctx).await {
                                            Ok(_) => return create_session_and_send(&username, &salt, &ctx).await,
                                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00015\"}".to_string(),&(e.to_string() + " | IEC00015"), 500, &ctx).await,
                                        }

                                    }
                                },
                                Err(_) => return Response::ok("{\"Error\":\"Activation failed. No password header, which is required for this endpoint.\"}"),
                            }
                        },
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00016\"}".to_string(),&(e.to_string() + " | IEC00016"), 500, &ctx).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Activation failed. The request is missing a username in the url.".to_string()).await,
            }
        },
        Err(_) => return err_specific("{\"Error\":\"Activation failed. The request is missing the activation code in the json input.)".to_string()).await
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
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_details(&username, &db).await {
                Ok(res) => return Ok(Response::from_json(&res).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00017\"}".to_string(),&(e.to_string() + " | IEC00017"), 500, &ctx).await,
            }    
                  
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00018\"}".to_string(),&(e.to_string() + " | IEC00018"), 500, &ctx).await,
    }
}


pub async fn deactivate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {    
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return err_specific("{\"Error\":\"".to_string() + &session_result.1 + "\"}").await
            }

            let username = session_result.1;
            
            if !db_fso::db_user_is_active(&username, &db).await {
                return send_failure(&ERROR_USER_NOT_ACTIVE.to_string(), 403).await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
                                Ok(exists) => if !exists {
                                    return err_specific("{\"Error\":\"User does not exist or may already be deactivated.\"}".to_string()).await;
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00019\"}".to_string(),&(e.to_string() + " | IEC00019"), 500, &ctx).await,
                            };
                
                            // Owners can only be deactivated by someone working directly with the database.
                            // But otherwise, you *can* deactivate yourself.
                            if target_user.email == username && authorizer_role != db_fso::UserRole::OWNER {
                                
                                match db_fso::db_deactivate_user(&username, &db).await {
                                    Ok(_) => return send_success(&"{\"Response\": \"User Deactivated\"}".to_string(), &"".to_string()).await,
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00020\"}".to_string(),&(e.to_string() + " | IEC00020"), 500, &ctx).await,
                                }

                            }

                            // these two types are not allowed to deactivate other users
                            match authorizer_role {
                                db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                _=> (),
                            }         
                                                                                    
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    if authorizer_role < target_user_role{
                                        match db_fso::db_deactivate_user(&target_user.email, &db).await {
                                            Ok(_) => return send_success(&"{\"Response\": \"User Deactivated\"}".to_string(), &"".to_string()).await,
                                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00021\"}".to_string(),&(e.to_string() + " | IEC00021"), 500, &ctx).await,
                                        }
                                    } else {
                                        return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await;
                                    }
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00022\"}".to_string(),&(e.to_string() + " | IEC00022"), 500, &ctx).await,                                
                            }               
                        },
                        Err(_) => return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00023\"}".to_string(),&(e.to_string() + " | IEC00023"), 500, &ctx).await, 
            }
            
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00024\"}".to_string(),&(e.to_string() + " | IEC00024"), 500, &ctx).await,
    }
}

pub async fn activate_user(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await
            }

            let username = session_result.1;

            match req.json::<EmailSubmission>().await {                                                        
                Ok(target_user) =>{
                    match db_fso::db_email_taken(&target_user.email, &db).await {
                        Ok(exists) => if !exists {
                            return err_specific("{\"Error\":\"User to be activated does not exist.\"}".to_string()).await;
                        },
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00025\"}".to_string(),&(e.to_string() + " | IEC00025"), 500, &ctx).await,
                    };

                    // make no changes if this user already exists
                    if db_fso::db_user_is_active(&target_user.email, &db).await {
                        return send_success(&"{\"Response\": \"User is already Active\"}".to_string(), &"".to_string()).await
                    }

                    // We need to see if the activating user is active, otherwise we should ignore
                    if !db_fso::db_user_is_active(&username, &db).await {
                        // Owners can only be deactivated by someone working directly with the database.
                        // But otherwise, you *can* deactivate yourself.
                        if target_user.email == username{
                            match db_fso::db_activate_user(&target_user.email, &db).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00026\"}".to_string(),&(e.to_string() + " | IEC00026"), 500, &ctx).await,
                            }
                        } else {
                            return send_failure(&ERROR_USER_NOT_ACTIVE.to_string(), 403).await
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
                                return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await
                            }
                            db_fso::UserRole::MAINTAINER => {
                                if target_user.email != username{
                                    let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                    return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await    
                                }
                            },
                            db_fso::UserRole::VIEWER => { 
                                if target_user.email != username{
                                    let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                    return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await
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
                                        Ok(_) => return send_success(&"{\"Response\": \"User Activated\"}".to_string(), &"".to_string()).await,
                                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00027\"}".to_string(),&(e.to_string() + " | IEC00027"), 500, &ctx).await,
                                    }
                                } else {
                                    return send_success(&"{\"Response\": \"User Activated\"}".to_string(), &"".to_string()).await
                                }
                            },
                            Err(e) => {
                                let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                                return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00028\"}".to_string(),&(e.to_string() + " | IEC00028"), 500, &ctx).await
                            }
                        }
                        },
                        Err(e) => {
                            let _ = db_fso::db_deactivate_user(&target_user.email, &db).await;
                            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00029\"}".to_string(),&(e.to_string() + " | IEC00029"), 500, &ctx).await
                        }
                    }    
                },
                Err(_) => return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await,
            }        
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00030\"}".to_string(),&(e.to_string() + " | IEC00030"), 500, &ctx).await,
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
                        Ok(b) => if !b { return send_failure(&"{\"Error\":\"Incorrect credentials! Please resubmit.\"}".to_string(), 403).await },
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00031\"}".to_string(),&(e.to_string() + " | IEC00031"), 500, &ctx).await,
                    }

                    let salt_result = db_fso::db_get_user_salt(&login.email, &ctx).await;

                    if salt_result.is_err() {
                        return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00139\"}".to_string(),&(salt_result.unwrap_err().to_string() + " | IEC00139"), 500, &ctx).await;
                    }

                    let salt = salt_result.unwrap();

                    match hash_string(&salt, &login.password).await {
                        Ok(hash) => {
                            if db_fso::db_check_password(&login.email, &hash, &db).await {
                                return create_session_and_send(&login.email, &salt, &ctx).await;
                            } else {
                                return send_failure(&"{\"Error\":\"Incorrect credentials! Please resubmit.\"}".to_string(), 403).await;
                            }
                        },
                        Err(_) => return err_specific("{\"Error\":\"Hashing function failed.\"}".to_string()).await,
                    }                    
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00032\"}".to_string(),&(e.to_string() + " | IEC00032"), 500, &ctx).await,
            }
        },
    Err(e) => err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00033\"}".to_string(),&(e.to_string() + " | IEC00033"), 500, &ctx).await,
    }

}

#[derive(Serialize, Deserialize)]
pub struct Password{
    password: String,
}

pub async fn user_change_password(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {

            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;
            match req.json::<Password>().await{
                Ok(password) => {
                    match check_password_requirements(&password.password).await{
                        Ok(_) => (),
                        Err(e) => return err_specific(format!("{{\"Error\":\"{}\"}}", e.to_string())).await,
                    }                                       

                    let salt_result = db_fso::db_get_user_salt(&username, &ctx).await;

                    if salt_result.is_err() {
                        return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00140\"}".to_string(),&(salt_result.unwrap_err().to_string() + " | IEC00140"), 500, &ctx).await;
                    }

                    let salt = salt_result.unwrap();                    

                    match hash_string(&salt, &password.password).await {                             
                        Ok(hash) => { 
                            match db_fso::db_set_new_pass(&username, &hash, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Password Changed!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00035\"}".to_string(),&(e.to_string() + " | IEC00035"), 500, &ctx).await,
                            }
                        },
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00036\"}".to_string(),&(e.to_string() + " | IEC00036"), 500, &ctx).await,
                    }                            
                },
                Err(_) => return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await,
            }
        },
        Err(e)=> err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00037\"}".to_string(),&(e.to_string() + " | IEC00037"), 500, &ctx).await,
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

pub async fn user_reset_password(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {   
    
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            let email = req.json::<EmailSubmission>().await;
            if email.is_err() {
                return err_specific(ERROR_BAD_REQUEST.to_string()).await;        
            }
            
            let successful_email = email.unwrap().email;

            if !EmailAddress::is_valid(&successful_email) {
                return err_specific(ERROR_BAD_REQUEST.to_string()).await;
            }
        
            match db_fso::db_is_user_banned_or_nonexistant(&successful_email, &db).await {
                Ok(exists) => if !exists {
                    return err_specific("{\"Error\":\"User is not fully registered or is banned.\"}".to_string()).await;
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00143\"}".to_string(),&(e.to_string() + " | IEC00143"), 500, &ctx).await,
            };

            let code = create_random_code().await;

            let salt_result = db_fso::db_get_user_salt(&successful_email, &ctx).await;

            if salt_result.is_err() {
                return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00153\"}".to_string(),&(salt_result.unwrap_err().to_string() + " | IEC00153"), 500, &ctx).await;
            }

            let salt = salt_result.unwrap();      

            match hash_string(&salt, &code).await {
                Ok(hashed_code) => {
                    match db_fso::db_add_code_reset(&successful_email, &hashed_code, &ctx).await{
                        Ok(_) => (),
                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00152\"}".to_string(),&(e.to_string() + " | IEC00152"), 500, &ctx).await,
                    }        
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please wait and try again. | IEC00153\"}".to_string(),&(e.to_string() + " | IEC00153"), 500, &ctx).await,
            }

            send_password_reset_email(&successful_email, &code, &ctx).await
        
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00142\"}".to_string(),&(e.to_string() + " | IEC00142"), 500, &ctx).await,

    }

}

#[derive(Serialize, Deserialize)]
struct PasswordReset {
    code: String,
    username: String,
    password: String, 
}

pub async fn user_reset_password_confirmed(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {    
    let request = req.json::<PasswordReset>().await;
    if request.is_err() {
        return err_specific(ERROR_BAD_REQUEST.to_string()).await;        
    }

    let good_request = request.unwrap();
    let username = &good_request.username;

    let salt_result = db_fso::db_get_user_salt(&username, &ctx).await;
    if salt_result.is_err() {
        return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00154\"}".to_string(),&(salt_result.unwrap_err().to_string() + " | IEC00154"), 500, &ctx).await;
    }

    let good_salt = salt_result.unwrap();
    let code = &good_request.code;

    match hash_string(&good_salt, &code).await {                             
        Ok(hashed_code) => {
            match db_fso::db_check_code(&username, &hashed_code, &ctx).await{
                Ok(_) => (),
                Err(e) => return err_specific(e.to_string()).await,
            }        
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00145\"}".to_string(),&(e.to_string() + " | IEC00145"), 500, &ctx).await,
    }

    let password = &good_request.password;

    match check_password_requirements(&password).await{
        Ok(_) => (),
        Err(e) => return err_specific(format!("{{\"Error\":\"{}\"}}", e.to_string())).await,
    }

    match hash_string(&good_salt, &password).await {                             
        Ok(hash) => { 
            match db_fso::db_set_new_pass(&username, &hash, &ctx).await {
                Ok(_) => return send_success(&"{\"Response\": \"Password Changed!\"}".to_string(), &"".to_string()).await,
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00146\"}".to_string(),&(e.to_string() + " | IEC00146"), 500, &ctx).await,
            }
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00147\"}".to_string(),&(e.to_string() + " | IEC00147"), 500, &ctx).await,
    }            

}

pub async fn user_upgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {    
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            if !db_fso::db_user_is_active(&username, &db).await {
                return send_failure(&ERROR_USER_NOT_ACTIVE.to_string(), 403).await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
                                Ok(exists) => if !exists {
                                    return err_specific("{\"Error\":\"User does not exist or may be deactivated.\"}".to_string()).await;
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00038\"}".to_string(),&(e.to_string() + " | IEC00038"), 500, &ctx).await,
                            };
                
                            // You *cannot* upgrade yourself.
                            if target_user.email == username {
                                return err_specific("{\"Error\":\"You cannot upgrade your own account.\"}".to_string()).await
                            }

                            // these two types are not allowed to deactivate other users
                            match authorizer_role {
                                db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                _=> (),
                            }         

                            // TODO! Extra check needed?                                                                                        
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    // We cannot upgrade Admins here.  Only when directly accessing the database.
                                    if authorizer_role < target_user_role && target_user_role > db_fso::UserRole::ADMIN {
                                        //db_upgrade_user(&target_user.email, &db).await;
                                        return send_success(&"{\"Response\": \"User Upgraded\"]".to_string(), &"".to_string()).await;
                                    } else {
                                        return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await;
                                    }
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00039\"}".to_string(),&(e.to_string() + " | IEC00039"), 500, &ctx).await,                                
                            }               
                        },
                        Err(_) => return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00040\"}".to_string(),&(e.to_string() + " | IEC00040"), 500, &ctx).await, 
            }
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00041\"}".to_string(),&(e.to_string() + " | IEC00041"), 500, &ctx).await,
    }
}

pub async fn user_downgrade_user_permissions(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {  
  
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            if !db_fso::db_user_is_active(&username, &db).await {
                return send_failure(&ERROR_USER_NOT_ACTIVE.to_string(), 403).await
            }

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {

                    match req.json::<EmailSubmission>().await {                                                        
                        Ok(target_user) =>{
                            match db_fso::db_has_active_user(&target_user.email, &db).await {
                                Ok(exists) => if !exists {
                                    return err_specific("{\"Error\":\"User does not exist or may be deactivated.\"}".to_string()).await;
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00042\"}".to_string(),&(e.to_string() + " | IEC00042"), 500, &ctx).await,
                            };
                
                            // You *cannot* upgrade yourself.
                            if target_user.email == username {
                                return err_specific("{\"Error\":\"You cannot downgrade your own account.\"}".to_string()).await
                            }

                            // these two types are not allowed to deactivate other users
                            match authorizer_role {
                                db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                                _=> (),
                            }         

                            // TODO! Do we need extra checks here?                                                                                        
                            match db_fso::db_get_user_role(&target_user.email, &db).await { 
                                Ok(target_user_role) => {
                                    // We cannot downgrade viewers.  Deactivating them is a different code path
                                    if authorizer_role < target_user_role && target_user_role < db_fso::UserRole::VIEWER {
                                        //db_downgrade_user(&target_user.email, &db).await;
                                        return worker::Response::ok("{\"Response\":\"User Upgraded\"}");
                                    } else {
                                        return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await;
                                    }
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00043\"}".to_string(),&(e.to_string() + " | IEC00043"), 500, &ctx).await,                                
                            }               
                        },
                        Err(_) => return send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00044\"}".to_string(),&(e.to_string() + " | IEC00044"), 500, &ctx).await, 
            }
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00045\"}".to_string(),&(e.to_string() + " | IEC00045"), 500, &ctx).await,
    }
}

pub async fn get_parse_types(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::ParseBehaviors, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(results) => return Ok(Response::from_json(&results.parse_behaviors).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00046\"}".to_string(),&(e.to_string() + " | IEC00046"), 500, &ctx).await,
    }
}

pub async fn get_parse_type(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::ParseBehaviors, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.parse_behaviors).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00047\"}".to_string(),&(e.to_string() + " | IEC00047"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}


pub async fn update_parse_type(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match req.json::<db_fso::ParseBehavior>().await {
                        Ok(parse_behavior) => {
                            if parse_behavior.behavior_id < 1 {
                                return err_specific("{\"Error\":\"Invalid behavior id, cannot update.\"}".to_string()).await;
                            }

                            if parse_behavior.behavior != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::ParseBehaviors, 0, &parse_behavior.behavior, &parse_behavior.behavior_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00048\"}".to_string(),&(e.to_string() + " | IEC00048"), 500, &ctx).await,
                                }    
                            }

                            if parse_behavior.description != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::ParseBehaviors, 1, &parse_behavior.description, &parse_behavior.behavior_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00049\"}".to_string(),&(e.to_string() + " | IEC00049"), 500, &ctx).await,
                                }
                            }

                            return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await

                        },
                        Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\n Make sure that the request json has a behavior_id, behavior, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.\"}").await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00050\"}".to_string(),&(e.to_string() + " | IEC00050"), 500, &ctx).await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00051\"}".to_string(),&(e.to_string() + " | IEC00051"), 500, &ctx).await,
    }
}

pub async fn delete_parse_type(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> {},
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00052\"}".to_string(),&(e.to_string() + " | IEC00052"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(_) =>{
                            match db_fso::db_generic_delete(db_fso::Table::ParseBehaviors, id, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00053\"}".to_string(),&(e.to_string() + " | IEC00053"), 500, &ctx).await,
                            }
                            
                        },
                        Err(_) => return err_specific("{\"Error\":\"Could not parse the parse behavior id as an integer, please resubmit!\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Please provide a parse behavior id to delete, and then resubmit.\"}".to_string()).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00054\"}".to_string(),&(e.to_string() + " | IEC00054"), 500, &ctx).await,
    }
}

pub async fn get_items(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::FsoItems, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Ok(Response::from_json(&result.fso_items).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await));
        },
        Err(e) => {
            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00055\"}".to_string(),&(e.to_string() + " | IEC00055"), 500, &ctx).await;
        }
    }
}

pub async fn get_item(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::FsoItems, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.fso_items).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00056\"}".to_string(),&(e.to_string() + " | IEC00056"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}

// const FSO_ITEMS_INSERT_QUERY: &str = "INSERT INTO fso_items (item_text, documentation, major_version, parent_id, table_id, deprecation_id, restriction_id, info_type, table_index, default_value) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";


#[derive(Serialize, Deserialize)]
pub struct NewItem{
    item_text: String,
    documentation: String,
    major_version: String, 
    parent_id: i32,
    table_id: i32,
    deprecation_id: i32,
    restriction_id: i32,
    info_type: String,
    table_index: i32,
    default_value: String,
}

pub async fn insert_item(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }  
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00057\"}".to_string(),&(e.to_string() + " | IEC00057"), 500, &ctx).await,
            }

            match req.json::<NewItem>().await{
                Ok(new_item) => {
                    if new_item.item_text.trim().is_empty()  {
                        return err_specific("{\"Error\":\"Item text cannot be empty.  Please resubmit your item.\"}".to_string()).await;
                    }

                    if new_item.major_version.is_empty() {
                        return err_specific("{\"Error\":\"Item major version must be specified.\"}".to_string()).await;
                    }

                    match Regex::new(DB_SEMVER_CHARACTERS) {
                        Ok(search_set) => {
                            match search_set.find(&new_item.major_version) {
                                Some(_) => return err_specific("{\"Error\":\"Disallowed semver characters found, please submit with a corrected majorversion.\"}".to_string()).await,
                                None => err_specific("{\"Error\":\"I'm not done yet come back later.\"}".to_string()).await,
                            }    
                        },
                        Err(e) => return Err(e.to_string().into())
                    }
                
                    

                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00058\"}".to_string(),&(e.to_string() + " | IEC00058"), 500, &ctx).await,
            }


        }, 
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00059\"}".to_string(),&(e.to_string() + " | IEC00059"), 500, &ctx).await
    }
}

pub async fn update_item(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match req.json::<db_fso::FsoItems>().await {
                        Ok(item) => {
                            if item.item_id < 0 {
                                return err_specific("{\"Error\":\"Invalid item id, cannot update.\"}".to_string()).await;
                            }

                            if item.default_value != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 0, &item.default_value, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00060\"}".to_string(),&(e.to_string() + " | IEC00060"), 500, &ctx).await,
                                }    
                            }

                            if item.deprecation_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 1, &item.deprecation_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00061\"}".to_string(),&(e.to_string() + " | IEC00061"), 500, &ctx).await,
                                }
                            }

                            if item.documentation != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 2, &item.documentation, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00062\"}".to_string(),&(e.to_string() + " | IEC00062"), 500, &ctx).await,
                                }
                            }

                            if item.info_type != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 3, &item.info_type, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00063\"}".to_string(),&(e.to_string() + " | IEC00063"), 500, &ctx).await,
                                }
                            }

                            if item.item_text != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 4, &item.item_text, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00064\"}".to_string(),&(e.to_string() + " | IEC00064"), 500, &ctx).await,
                                }
                            }

                            if item.major_version != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 5, &item.major_version, &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00065\"}".to_string(),&(e.to_string() + " | IEC00065"), 500, &ctx).await,
                                }
                            }
                            
                            if item.parent_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 6, &item.parent_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00066\"}".to_string(),&(e.to_string() + " | IEC00066"), 500, &ctx).await,
                                }
                            }

                            if item.restriction_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 7, &item.restriction_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00067\"}".to_string(),&(e.to_string() + " | IEC00067"), 500, &ctx).await,
                                }
                            }

                            if item.table_id > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::FsoItems, 8, &item.table_id.to_string(), &item.item_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00068\"}".to_string(),&(e.to_string() + " | IEC00068"), 500, &ctx).await,
                                }
                            }

                            return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await

                        },
                        Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\nMake sure that the request json has an item_id, behavior, and description, even if not updating.  If not updating a field (id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or more negative number for ids for no update.  Echo back other values for no update.\"}").await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00069\"}".to_string(),&(e.to_string() + " | IEC00069"), 500, &ctx).await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00070\"}".to_string(),&(e.to_string() + " | IEC00070"), 500, &ctx).await,
    }
}

pub async fn delete_item(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> {},
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00071\"}".to_string(),&(e.to_string() + " | IEC00071"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(_) =>{
                            match db_fso::db_generic_delete(db_fso::Table::FsoItems, id, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00072\"}".to_string(),&(e.to_string() + " | IEC00072"), 500, &ctx).await,
                            }
                            
                        },
                        Err(_) => return err_specific("{\"Error\":\"Could not parse the item id as an integer, please resubmit!\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Please provide a item id to delete, and then resubmit.\"}".to_string()).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00073\"}".to_string(),&(e.to_string() + " | IEC00073"), 500, &ctx).await,
    }
}

pub async fn get_tables(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::FsoTables, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Ok(Response::from_json(&result.fso_tables).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await));
        },
        Err(e) => {
            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00074\"}".to_string(),&(e.to_string() + " | IEC00074"), 500, &ctx).await;
        }
    }
}

pub async fn get_table(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::FsoTables, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.fso_tables).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00075\"}".to_string(),&(e.to_string() + " | IEC00075"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}

pub async fn get_aliases(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::TableAliases, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Ok(Response::from_json(&result.table_aliases).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await));
        },
        Err(e) => {
            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00076\"}".to_string(),&(e.to_string() + " | IEC00076"), 500, &ctx).await;
        }
    }
}

pub async fn get_alias(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::TableAliases, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.table_aliases).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00077\"}".to_string(),&(e.to_string() + " | IEC00077"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}

pub async fn update_alias(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match req.json::<db_fso::TableAlias>().await {
                        Ok(table_alias) => {
                            if table_alias.alias_id < 0 {
                                return err_specific("{\"Error\":\"Invalid table alias id, cannot update.\"}".to_string()).await;
                            }

                            if table_alias.filename != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::TableAliases, 0, &table_alias.filename, &table_alias.alias_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00078\"}".to_string(),&(e.to_string() + " | IEC00078"), 500, &ctx).await,
                                }    
                            }

                            if table_alias.table_id > -2{
                                match db_fso::db_generic_update_query(&db_fso::Table::TableAliases, 1, &table_alias.table_id.to_string(), &table_alias.alias_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00079\"}".to_string(),&(e.to_string() + " | IEC00079"), 500, &ctx).await,
                                }
                            }

                            return Response::ok("Success!")

                        },
                        Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\nMake sure that the request json has an alias_id, filename, and table_id, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.\"}").await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00080\"}".to_string(),&(e.to_string() + " | IEC00080"), 500, &ctx).await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00081\"}".to_string(),&(e.to_string() + " | IEC00081"), 500, &ctx).await,
    }
}

pub async fn delete_alias(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> {},
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00082\"}".to_string(),&(e.to_string() + " | IEC00082"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(_) =>{
                            match db_fso::db_generic_delete(db_fso::Table::TableAliases, id, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00083\"}".to_string(),&(e.to_string() + " | IEC00083"), 500, &ctx).await,
                            }
                            
                        },
                        Err(_) => return err_specific("{\"Error\":\"Could not parse the alias id as an integer, please resubmit!\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Please provide a alias id to delete, and then resubmit.\"}".to_string()).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00084\"}".to_string(),&(e.to_string() + " | IEC00084"), 500, &ctx).await,
    }
}

pub async fn get_restrictions(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::Restrictions, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Ok(Response::from_json(&result.restrictions).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await));
        },
        Err(e) => {
            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00085\"}".to_string(),&(e.to_string() + " | IEC00085"), 500, &ctx).await;
        }
    }
}

pub async fn get_restriction(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::Restrictions, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.restrictions).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00086\"}".to_string(),&(e.to_string() + " | IEC00086"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}

pub async fn update_restriction(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match req.json::<db_fso::Restrictions>().await {
                        Ok(restriction) => {
                            if restriction.restriction_id < 0 {
                                return err_specific("{\"Error\":\"Invalid restriction id, cannot update.\"}".to_string()).await;
                            }

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 0, &restriction.illegal_value_float.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00087\"}".to_string(),&(e.to_string() + " | IEC00087"), 500, &ctx).await,
                            }    

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 1, &restriction.illegal_value_int.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00088\"}".to_string(),&(e.to_string() + " | IEC00088"), 500, &ctx).await,
                            }
                            
                            if restriction.max_string_length > -2 {
                                match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 2, &restriction.max_string_length.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00089\"}".to_string(),&(e.to_string() + " | IEC00089"), 500, &ctx).await,
                                }    
                            }

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 3, &restriction.max_value.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00090\"}".to_string(),&(e.to_string() + " | IEC00090"), 500, &ctx).await,
                            }    

                            match db_fso::db_generic_update_query(&db_fso::Table::Restrictions, 4, &restriction.min_value.to_string(), &restriction.restriction_id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00091\"}".to_string(),&(e.to_string() + " | IEC00091"), 500, &ctx).await,
                            }    

                            return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await

                        },
                        Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\nMake sure that the request json has a restriction_id, illegal_value_float, illegal_value_int, max_string_length, max_value, min_value, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.\"}").await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00092\"}".to_string(),&(e.to_string() + " | IEC00092"), 500, &ctx).await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00093\"}".to_string(),&(e.to_string() + " | IEC00093"), 500, &ctx).await,
    }
}

pub async fn delete_restriction(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> {},
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00094\"}".to_string(),&(e.to_string() + " | IEC00094"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(_) =>{
                            match db_fso::db_generic_delete(db_fso::Table::Restrictions, id, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00095\"}".to_string(),&(e.to_string() + " | IEC00095"), 500, &ctx).await,
                            }
                            
                        },
                        Err(_) => return err_specific("{\"Error\":\"Could not parse the restriction id as an integer, please resubmit!\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Please provide a restriction id to delete, and then resubmit.\"}".to_string()).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00096\"}".to_string(),&(e.to_string() + " | IEC00096"), 500, &ctx).await,
    }
}

pub async fn get_deprecations(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match db_fso::db_generic_search_query(&db_fso::Table::Deprecations, 0, &"".to_string(), &"".to_string(), &ctx).await {
        Ok(result) => {
            return Ok(Response::from_json(&result.deprecations).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await));
        },
        Err(e) => {
            return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00097\"}".to_string(),&(e.to_string() + " | IEC00097"), 500, &ctx).await;
        }
    }
}

pub async fn get_deprecation(_: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.param("id"){
        Some(parameter) => match db_fso::db_generic_search_query(&db_fso::Table::Deprecations, 1, parameter, &"".to_string(), &ctx).await {
            Ok(results) => return Ok(Response::from_json(&results.deprecations).unwrap().with_headers(add_mandatory_headers(&"".to_string()).await)),
            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00098\"}".to_string(),&(e.to_string() + " | IEC00098"), 500, &ctx).await,
        },
        None => return err_specific("{\"Error\":\"Internal Server Error, route parameter mismatch!\"}".to_string()).await,
    }
}

pub async fn update_deprecation(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match req.json::<db_fso::Deprecations>().await {
                        Ok(deprecation) => {
                            if deprecation.deprecation_id < 0 {
                                return err_specific("{\"Error\":\"Invalid deprecation id, cannot update.\"}".to_string()).await;
                            }

                            if deprecation.date != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::Deprecations, 0, &deprecation.date, &deprecation.deprecation_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00099\"}".to_string(),&(e.to_string() + " | IEC00099"), 500, &ctx).await,
                                }    
                            }

                            if deprecation.version != "~!!NO UPDATE!!~"{
                                match db_fso::db_generic_update_query(&db_fso::Table::Deprecations, 1, &deprecation.version, &deprecation.deprecation_id.to_string(),  &ctx).await {
                                    Ok(_) => (),
                                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00100\"}".to_string(),&(e.to_string() + " | IEC00100"), 500, &ctx).await,
                                }
                            }

                            return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await

                        },
                        Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\nMake sure that the request json has a deprecation_id, date, and version, even if not updating.  If not updating a field (deprecation_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.\"}").await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00101\"}".to_string(),&(e.to_string() + " | IEC00101"), 500, &ctx).await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00102\"}".to_string(),&(e.to_string() + " | IEC00102"), 500, &ctx).await,
    }
}

pub async fn delete_deprecation(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> {},
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00103\"}".to_string(),&(e.to_string() + " | IEC00103"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(_) =>{
                            match db_fso::db_generic_delete(db_fso::Table::ParseBehaviors, id, &ctx).await {
                                Ok(_) => return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00104\"}".to_string(),&(e.to_string() + " | IEC00104"), 500, &ctx).await,
                            }
                            
                        },
                        Err(_) => return err_specific("{\"Error\":\"Could not parse the deprecation id as an integer, please resubmit!\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Please provide a deprecation id to delete, and then resubmit.\"}".to_string()).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00105\"}".to_string(),&(e.to_string() + " | IEC00105"), 500, &ctx).await,
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
            let session_result = header_session_is_valid(&req, &db, &ctx).await;

            match req.json::<BugReport>().await{
                Ok(report) =>{
                    if report.description.is_empty() {
                        return err_specific("{\"Error\":\"Please provide a description when submitting a bug report.\"}".to_string()).await
                    }

                    let mut username = "Anonymous User".to_string();
                    if session_result.0 {
                        username = session_result.1;
                    }

                    match db_fso::db_insert_bug_report(&username, &report.bug_type, &report.description, &ctx).await {
                        Ok(_) => send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await,
                        Err(e) => err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00106\"}".to_string(),&(e.to_string() + " | IEC00106"), 500, &ctx).await,
                    }
        
                }, 
                Err(e) => err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00107\"}".to_string(),&(e.to_string() + " | IEC00107"), 500, &ctx).await,




            }
        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00108\"}".to_string(),&(e.to_string() + " | IEC00108"), 500, &ctx).await,
    }
}

pub async fn resolve_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         
                    match ctx.param("id"){
                        Some(id) => {
                            match id.parse::<i32>(){
                                Ok(parsed_id) =>{
                                    if parsed_id < 0 {
                                        return err_specific("{\"Error\":\"Invalid bug report id, cannot update.\"}".to_string()).await;
                                    }

                                    match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"3".to_string(), &id,  &ctx).await {
                                        Ok(_) => (),
                                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00109\"}".to_string(),&(e.to_string() + " | IEC00109"), 500, &ctx).await,
                                    }
                                
                                    return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await
                                }
                                Err(_) => return err_specific("{\"Error\":\"Bug report id cannot be parsed as an integer, please resubmit your request.\"}".to_string()).await,
                            }
                        },
                        None => return err_specific("{\"Error\":\"Please submit an id in the url as part of the request to acknowledge a bug report.\"}".to_string()).await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00110\"}".to_string(),&(e.to_string() + " | IEC00110"), 500, &ctx).await,
            }
        }
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00111\"}".to_string(),&(e.to_string() + " | IEC00111"), 500, &ctx).await,
    }
}


pub async fn unresolve_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::VIEWER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        db_fso::UserRole::MAINTAINER => return send_failure(&ERROR_INSUFFICIENT_PERMISSISONS.to_string(), 403).await,
                        _=> (),
                    }         

                    match ctx.param("id"){
                        Some(id) => {
                            match id.parse::<i32>(){
                                Ok(parsed_id) =>{
                                    if parsed_id < 0 {
                                            return err_specific("{\"Error\":\"Invalid bug report id, cannot update.\"}".to_string()).await;
                                    }

                                    match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"0".to_string(), &id.to_string(),  &ctx).await {
                                        Ok(_) => (),
                                        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00112\"}".to_string(),&(e.to_string() + " | IEC00112"), 500, &ctx).await,
                                    }

                                    return send_success(&"{\"Response\": \"Success!\"}".to_string(), &"".to_string()).await
                                },

                                Err(_) => return err_specific("{\"Error\":\"Bug report id cannot be parsed as an integer, please resubmit your request.\"}".to_string()).await,
                            }
                        }
                        None => return err_specific("{\"Error\":\"Please submit an id in the url as part of the request to acknowledge a bug report.\"}".to_string()).await,
                    }
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00113\"}".to_string(),&(e.to_string() + " | IEC00113"), 500, &ctx).await,
            }
        }
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00114\"}".to_string(),&(e.to_string() + " | IEC00114"), 500, &ctx).await,
    }
}


pub async fn acknowledge_bug_report(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    match ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
            }

            let username = session_result.1;

            match db_fso::db_get_user_role(&username, &db).await {                 
                Ok(authorizer_role) => {
                    match authorizer_role {
                        db_fso::UserRole::OWNER => (),
                        db_fso::UserRole::ADMIN => (),
                        _=> return err_specific("{\"Error\":\"Only administrators can acknowledge bug reports\"}".to_string()).await,
                    }         
                },
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00115\"}".to_string(),&(e.to_string() + " | IEC00115"), 500, &ctx).await,
            }

            match ctx.param("id"){
                Some(id) => {
                    match id.parse::<i32>(){
                        Ok(parsed_id) =>{
                            if parsed_id < 0 {
                                return err_specific("{\"Error\":\"Invalid bug report id, cannot update.\"}".to_string()).await;
                            }
        
                            match db_fso::db_generic_search_query(&db_fso::Table::BugReports, 0, &id, &"".to_string(), &ctx).await {
                                Ok(bug_report_result) => {
                                    if bug_report_result.bug_reports.is_empty() {
                                        return err_specific("{\"Error\":\"Could not find a matching bug report.\"}".to_string()).await;
                                    }
        
                                },
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00116\"}".to_string(),&(e.to_string() + " | IEC00116"), 500, &ctx).await,
                            }
        
                            match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 0, &"1".to_string(), &id.to_string(),  &ctx).await {
                                Ok(_) => (),
                                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00117\"}".to_string(),&(e.to_string() + " | IEC00117"), 500, &ctx).await,
                            }
        
                            return Response::ok("{\"Response\": \"Bug Report Successfully Updated!\"}")
                        },
                        Err(_) => return err_specific("{\"Error\":\"Bug report id cannot be parsed as an integer, please resubmit your request.\"}".to_string()).await,
                    }
                    
                },

                None => return err_specific("{\"Error\":\"Please submit an id in the url as part of the request to acknowledge a bug report.\"}".to_string()).await,
            }

        }
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00118\"}".to_string(),&(e.to_string() + " | IEC00118"), 500, &ctx).await,
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
            let session_result = header_session_is_valid(&req, &db, &ctx).await;
            if !session_result.0 {
                return send_failure(&ERROR_NOT_LOGGED_IN.to_string(), 403).await
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
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00119\"}".to_string(),&(e.to_string() + " | IEC00119"), 500, &ctx).await,
            }

            let bug_id: i32; 

            // MAJOR TODO!!! getting the id from the URL, we have not been checking that the id is numeric, so we need to go back and verify those are correct.
            // Here is an example of it done correctly, below.
            match ctx.param("id"){
                Some(id) => { 
                    match id.parse::<i32>() {
                        Ok(parsed) => bug_id = parsed,
                        Err(_) => return err_specific("{\"Error\":\"Cannot parse the supplied bug report id.\"}".to_string()).await,
                    }
                },
                None => return err_specific("{\"Error\":\"Invalid bug report id, cannot update.\"}".to_string()).await,
            }

            if !administrator {
                match db_fso::db_generic_search_query(&db_fso::Table::Users, 2, &username, &"".to_string(), &ctx).await {
                    Ok(user_result) => {
                        if user_result.users.is_empty(){
                            return err_specific("{\"Error\":\"Could not find a matching user for the username logged in somehow. You should probably submit a new bug report.\"}".to_string()).await
                        }

                        match db_fso::db_generic_search_query(&db_fso::Table::BugReports, 1, &bug_id.to_string(), &"".to_string(), &ctx).await {
                            Ok(bug_report_result) => {
                                if user_result.users[0].id != bug_report_result.bug_reports[0].user_id {
                                    return err_specific("{\"Error\":\"Only the reporter of a bug or an administrator can edit the contents of a bug report.\"}".to_string()).await
                                }
                            }
                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00120\"}".to_string(),&(e.to_string() + " | IEC00120"), 500, &ctx).await,
                        }
                    },
                    Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00121\"}".to_string(),&(e.to_string() + " | IEC00121"), 500, &ctx).await,
                }
            }



            match req.json::<BugReportInfo>().await {
                Ok(bug_info) => {
                    if bug_info.bug_type != "~!!NO UPDATE!!~"{
                        match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 1, &bug_info.bug_type, &bug_id.to_string(),  &ctx).await {
                            Ok(_) => (),
                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00122\"}".to_string(),&(e.to_string() + " | IEC00122"), 500, &ctx).await,
                        }    
                    }

                    if bug_info.description != "~!!NO UPDATE!!~"{
                        match db_fso::db_generic_update_query(&db_fso::Table::BugReports, 2, &bug_info.description, &bug_id.to_string(),  &ctx).await {
                            Ok(_) => (),
                            Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00123\"}".to_string(),&(e.to_string() + " | IEC00123"), 500, &ctx).await,
                        }
                    }

                    return send_success(&"{\"Response\":\"Bug report successfully updated!\"}".to_string(), &"".to_string()).await

                },
                Err(e) => return err_specific("{\"Error\":\"".to_string() + &e.to_string() + "\nMake sure that the request json has an bug_type, and description, even if not updating.  If not updating a field (parse_id cannot be updated) mark a string type with \"~!!NO UPDATE!!~\". Use -2 or a more negative number for ids. Echo back other values.\"}").await,
            }

        },
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00124\"}".to_string(),&(e.to_string() + " | IEC00124"), 500, &ctx).await,
    }
}

// SECTION!! generic server tasks
pub async fn  header_has_token(req: &Request) -> Option<worker::Result<Response>> {
    match req.headers().has("Cookie"){
        Ok(res) => {
            if res { 
                return None 
            }
        },
        Err(_) => (),
    }

    match req.headers().has("GanymedeToken"){
        Ok(res) => {
            if res { 
                return None 
            } else {
                return Some(send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await)                
            }        
        },
        Err(_) => return Some(send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await),
    }
}

pub async fn header_has_username(req: &Request) -> Option<worker::Result<Response>> {
    match req.headers().has("username"){
        Ok(res) => {
            if res { 
                return None 
            } else {
                return Some(send_failure(&ERROR_BAD_REQUEST.to_string(), 403).await)
            }        
        },
        Err(_) => return Some(err_specific("{\"Error\":\"Could not find a username header, please check your inputs and try again. | IEC00126\"}".to_string()).await),
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
    match req.headers().get("GanymedeToken"){
        Ok(token_option) => {
            match token_option {
                Some(token) => return Ok(token),
                None => (),
            }
        },
        Err(_) => (),
    }

    match req.headers().get("Cookie"){
        Ok(cookies) => {
            match cookies {
                Some(cookie_string) => {
                        match cookie_string.find("GanymedeToken=") {
                            Some(index)=> {
                                if cookie_string.len() > index + 77{
                                    return Ok(cookie_string[index + 14..index + 78].to_string());
                                }
                            },
                            None => (),
                        }
                        return Err("All login token retreival methods failed. Check your input. IEC00135".to_string().into());
                    }
                None => { 
                    return Err("All login token retreival methods failed. Check your input. IEC00136".to_string().into());
                }
            }
        },
        Err(_) => return Err("All login token retreival methods failed. Check your input. IEC00137".to_string().into()),
    }

}

pub async fn create_session_and_send(email: &String, salt: &String, ctx: &RouteContext<()>) -> worker::Result<Response> {
    let login_token = create_random_string().await;
    let hashed_string: String;                                

    match hash_string(&salt, &login_token).await {
        Ok(hashed) => hashed_string = hashed,
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00133\"}".to_string(),&(e.to_string() + " | IEC00133"), 500, &ctx).await,
    }

    // We give the user two hours to do what they need to do.
    match db_fso::db_session_add(&hashed_string, &email, &(Utc::now() + TimeDelta::hours(2)).to_string(), ctx).await {
        // remember! double {{ }} needed to escape here, even on the right side.
        Ok(_) => return send_success(&"".to_string(), &login_token).await,
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00134\"}".to_string(),&(e.to_string() + " | IEC00134"), 500, &ctx).await,
    }
}

pub async fn hash_string(hasher: &String, string: &String) -> worker::Result<String> {
    // Right here we need to do a little bit of server-only stuff!! For safety.  Only on production!

    // So this needs some documentation.
    // Basically, we need to convert the string into its u8 array and then into it's u64 array, because that is what randChaCha accepts
    let bytes = hasher.as_bytes();
    
    if bytes.is_empty() {
        return Err("Empty salt, cannot login.".to_string().into());
    }

    let mut counter = 0;
    let mut hasher_seed: u64 = 0;

    for byte in bytes.bytes() {
        hasher_seed *= 256; 
        match byte{
            Ok(b) => hasher_seed += b as u64,
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
    let rng = rand_chacha::ChaCha12Rng::seed_from_u64(hasher_seed);
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

pub async fn create_random_code() -> String {    
    return rand::thread_rng()
    .gen_range(100000..999999)
    .to_string()
}

// this is a big one.  We'll need to 1. Lookup an entry on username/tokens
// 2. Compare the token they gave us and see if it matches the username. 
// 3. See if the token is still valid.
pub async fn header_session_is_valid(req: &Request, db: &D1Database, ctx: &RouteContext<()>) -> (bool, String)  {
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
            
            let salt_result = db_fso::db_get_user_salt(&return_tuple.1, ctx).await;

            if salt_result.is_err() {
                return_tuple.1 = salt_result.unwrap_err().to_string();
                return return_tuple;
            }

            let salt = salt_result.unwrap();

            let hashed_token = hash_string(&salt, &token).await.unwrap();

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

pub async fn send_password_reset_email(address : &String, code: &String, ctx: &RouteContext<()>) -> worker::Result<worker::Response> {
    if !(EmailAddress::is_valid(&address)){
        return err_specific(format!("{{\"Error\":\"Tried to send automated email to invalid email address {}\"}}", address)).await
    }

    let mut headers : Headers = Headers::new();
    match headers.append("content-type", "application/json"){
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00127\"}".to_string(),&(e.to_string() + " | IEC00127"), 500, &ctx).await,
    }

    match headers.append("accept", "application/json") {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00128\"}".to_string(),&(e.to_string() + " | IEC00128"), 500, &ctx).await,
    }

    match headers.append("api-key", secrets::SMTP_API_KEY) {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00129\"}".to_string(),&(e.to_string() + " | IEC00129"), 500, &ctx).await,
    }

    let mut message: EmailMessage = EmailMessage::create_password_reset_email(&code);
    message.to.push(FullEmailAddress::create_full_email("User".to_string(), address.to_string()));

    let jvalue_out : JsValue;

    match serde_json::to_string(&message) {
        Ok(json_message) => jvalue_out = JsValue::from_str(&json_message),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00130\"}".to_string(),&(e.to_string() + " | IEC00130"), 500, &ctx).await,
    }

    let mut outbound_request = RequestInit::new();
    outbound_request.with_method(Method::Post).with_headers(headers).with_body(Some(jvalue_out));
    
    let imminent_request = worker::Request::new_with_init("https://api.brevo.com/v3/smtp/email", &outbound_request).unwrap();
    
    match worker::Fetch::Request(imminent_request).send().await {
        Ok(mut res) => { 
            match res.text().await {
                Ok(_) => return Response::ok("{\"Response\":\"Email sent!\"}"),
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00131\"}".to_string(),&(e.to_string() + " | IEC00131"), 500, &ctx).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00132\"}".to_string(),&(e.to_string() + " | IEC00132"), 500, &ctx).await,
    }

}

pub async fn send_confirmation_email(address : &String, activation_key : &String, ctx: &RouteContext<()>) -> worker::Result<worker::Response> {
    if !(EmailAddress::is_valid(&address)){
        return err_specific(format!("{{\"Error\":\"Tried to send automated email to invalid email address {}\"}}", address)).await
    }

    let mut headers : Headers = Headers::new();
    match headers.append("content-type", "application/json"){
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00127\"}".to_string(),&(e.to_string() + " | IEC00127"), 500, &ctx).await,
    }

    match headers.append("accept", "application/json") {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00128\"}".to_string(),&(e.to_string() + " | IEC00128"), 500, &ctx).await,
    }

    match headers.append("api-key", secrets::SMTP_API_KEY) {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00129\"}".to_string(),&(e.to_string() + " | IEC00129"), 500, &ctx).await,
    }

    let mut message: EmailMessage = EmailMessage::create_activation_email(activation_key);
    message.to.push(FullEmailAddress::create_full_email("User".to_string(), address.to_string()));

    let jvalue_out : JsValue;

    match serde_json::to_string(&message) {
        Ok(json_message) => jvalue_out = JsValue::from_str(&json_message),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00130\"}".to_string(),&(e.to_string() + " | IEC00130"), 500, &ctx).await,
    }

    let mut outbound_request = RequestInit::new();
    outbound_request.with_method(Method::Post).with_headers(headers).with_body(Some(jvalue_out));
    
    let imminent_request = worker::Request::new_with_init("https://api.brevo.com/v3/smtp/email", &outbound_request).unwrap();
    
    match worker::Fetch::Request(imminent_request).send().await {
        Ok(mut res) => { 
            match res.text().await {
                Ok(_) => return Response::ok("{\"Response\":\"Email sent!\"}"),
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00131\"}".to_string(),&(e.to_string() + " | IEC00131"), 500, &ctx).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00132\"}".to_string(),&(e.to_string() + " | IEC00132"), 500, &ctx).await,
    }

}

// Regular response when successful, allows cross origin requests (necessary for API)
pub async fn send_success(body: &String, token: &String) -> worker::Result<Response> {
    return Ok(Response::from_html(body)?.with_headers(add_mandatory_headers(token).await));
}

// Regular response when successful, allows cross origin requests (necessary for API)
pub async fn send_failure(body: &String, code: u16) -> worker::Result<Response> {
    return Ok(Response::from_html(body)?.with_headers(add_mandatory_headers(&"".to_string()).await).with_status(code));
}

pub async fn send_cors(_: Request, _: RouteContext<()>) -> worker::Result<Response> {
    return Ok(Response::from_html("{\"Response\":\"See headers for options.\"}")?.with_headers(add_mandatory_headers(&"".to_string()).await))
}

pub async fn add_mandatory_headers(token: &String) -> worker::Headers {
    let mut headers: Headers = Headers::new();

    headers.set("Access-Control-Allow-Origin", "https://www.fsotables.com").unwrap();
    headers.set("Access-Control-Allow-Methods", "GET,PATCH,POST,PUT,DELETE").unwrap();
//    headers.set("Access-Control-Allow-Headers", "username,Set-Cookie,GanymedeToken").unwrap();
//    headers.set("Access-Control-Allow-Credentials","true").unwrap();
//    headers.set("Access-Control-Max-Age", "100000").unwrap();
    if !token.is_empty() {
        match headers.set("Set-Cookie", &format!("GanymedeToken={}; SameSite=Lax; Path=/; Httponly; Secure; Expires={}", token, ( Utc::now() + TimeDelta::days(7) + TimeDelta::seconds(5) ))) {  //)) {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    return headers
}

/// CODE 403
const ERROR_INSUFFICIENT_PERMISSISONS: &str = "{\"Error\": \"This operation is not authorizable via our API at your access level.\"}";
/// CODE 403
const ERROR_NOT_LOGGED_IN: &str = "{\"Error\": \"You must be logged and provide an access token to access this endpoint.\"}";
/// CODE 403
const ERROR_USER_NOT_ACTIVE: &str = "{\"Error\": \"The user must be active before it can authorize this type of action\"}";
/// CODE 404
//const ERR_API_FALLBACK: &str = "{\"Error\": \"A method for this API route does not exist.\"}";

/// CODE 403
const ERROR_BAD_REQUEST: &str = "{\"Error\": \"Bad request, check your headers and/or JSON input.\"}";

pub async fn err_specific(e: String) -> worker::Result<Response> {
    send_failure(&e, 500).await    
}

pub async fn err_specific_and_add_report(mut external: String, internal: &String, code: u16, ctx: &RouteContext<()>) -> worker::Result<Response> {
    
    match db_fso::db_insert_error_record(&internal, ctx).await {
        Ok(_) => {},
        Err(e)=> {
            
            let error_record_result = format!(",\"Addendum\": \"Also, the internal error tracker could not save this error report because of \\\"{}\\\".  Please let Cyborg know.\"", e.to_string());
            let _a = external.pop();
            external += &error_record_result;
        },
    }

    send_failure(&external, code).await
}

/*
use worker::*;

#[derive(Deserialize)]
struct Registration {
	email: String,
	password: String,
}
*/
