use crate::{db_fso::*, DB_TIME_FORMAT};

use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2
};
use chrono::{Utc, TimeDelta};
use rand::*;
use rand::distributions::Alphanumeric;
use serde_json::from_str;
use std::io::Read;
use worker::*;


pub async fn  header_has_token(req: &Request) -> Option<worker::Result<Response>> {
    // Most of the time the cookie header has the token we're looking for
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
        Err(_) => return Some(err_specific("{\"Error\":\"Could not find a username header, please check your inputs and try again.\"}".to_string()).await),
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

// wrapper for regular lapsing session function
pub async fn maybe_renew_lapsing_session_no_salt(old_session_id: i32, old_session_timestamp: i64, username: &String, ctx: &RouteContext<()>) -> Result<String> {
    match db_get_user_salt(&username, &ctx).await {
        Ok(salt) => return maybe_renew_lapsing_session(old_session_id, old_session_timestamp, &salt, ctx).await,
        Err(e) => return Err(e.into()),
    }
}

pub async fn maybe_renew_lapsing_session(old_session_id: i32, old_session_timestamp: i64, salt: &String, ctx: &RouteContext<()>) -> Result<String> {
    let new_time =  from_str::<i64>(&(Utc::now() + TimeDelta::days(11)).format(DB_TIME_FORMAT).to_string());

    if new_time.is_err(){
        return Err((new_time.unwrap_err().to_string() + " Need this to work to have a new session.").into());
    }

    if old_session_timestamp < new_time.unwrap() {
        return renew_session(old_session_id, salt, ctx).await
    } else {
        return Ok("".to_string())
    }
}

pub async fn renew_session(old_session_id: i32, salt: &String, ctx: &RouteContext<()>) -> Result<String> {
    let login_token = create_random_string().await;
    let hashed_string: String;                                

    match hash_string(&salt, &login_token).await {
        Ok(hashed) => hashed_string = hashed,
        Err(e) => return Err(e.into()),
    }

    match db_renew_session(&hashed_string, old_session_id, &(Utc::now() + TimeDelta::days(14)).format(DB_TIME_FORMAT).to_string(), ctx).await {
        Ok(_) => return Ok(hashed_string), 
        Err(e) => return Err(e.into()),
    }
}

pub async fn create_session_and_send(email: &String, salt: &String, ctx: &RouteContext<()>) -> worker::Result<Response> {
    let login_token = create_random_string().await;
    let hashed_string: String;                                

    match hash_string(&salt, &login_token).await {
        Ok(hashed) => hashed_string = hashed,
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00133\"}".to_string(),&(e.to_string() + " | IEC00133"), 500, &ctx).await,
    }

    // We give the user seven days to do what they need to do.
    match db_session_add(&hashed_string, &email, &(Utc::now() + TimeDelta::days(7)).format(DB_TIME_FORMAT).to_string(), ctx).await {
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

// this is a big one.  We'll need to lookup an entry on username/tokens, compare the token they gave us and see if it matches the username. 
// See if the token is still valid, and look up and return the session ID and expiration time. (only going to update sessions when the user has not be active for two days)
// The return type is valid, Error/username, hash, expiration, id
pub async fn header_session_is_valid(req: &Request, db: &D1Database, ctx: &RouteContext<()>) -> (bool, String, String, i64, i64)  {
    let mut return_tuple = (false, "".to_string(), "".to_string(), -1, -1);
    
    // RETURNING SOME IS BAD HERE and means we don't have a header!
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

    // I think here Some is bad too
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
                return_tuple.1 = "Failed to get username from header.".to_string();
                return return_tuple;
            }
            
            let salt_result = db_get_user_salt(&return_tuple.1, ctx).await;

            if salt_result.is_err() {
                return_tuple.1 = salt_result.unwrap_err().to_string();
                return return_tuple;
            }

            let salt = salt_result.unwrap();

            let hashed_token = hash_string(&salt, &token).await.unwrap();

            match db_check_token(&return_tuple.1, &hashed_token, Utc::now().format(DB_TIME_FORMAT).to_string(), &db).await {
                Ok(result) => {
                    return_tuple.0 = result.0;
                    return_tuple.3 = result.1;
                    return_tuple.4 = result.2;
                },
                Err(e) => return_tuple.1 = e.to_string(),
            }

            return_tuple.2 = hashed_token;
            return return_tuple
        },
        Err(e) => return_tuple.1 = e.to_string(),     
    }    
    
    return return_tuple
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
    let headers: Headers = Headers::new();
//
    headers.set("Access-Control-Allow-Origin", "https://fsotables.com").unwrap();
    headers.set("Access-Control-Allow-Methods", "GET,PATCH,POST,PUT,DELETE").unwrap();
    headers.set("Access-Control-Allow-Headers", "username,Set-Cookie,GanymedeToken,password").unwrap();
    headers.set("Access-Control-Allow-Credentials","true").unwrap();
    headers.set("Access-Control-Max-Age", "100000").unwrap();
    if !token.is_empty() {
        match headers.set("Set-Cookie", &format!("GanymedeToken={}; SameSite=None; Path=/; Httponly; Secure; Expires={}; Domain=fsotables.com;", token, ( Utc::now() + TimeDelta::days(28) - TimeDelta::seconds(5) ).to_rfc2822())) {  //)) {
            Ok(_) => {},
            Err(_) => {},
        }
    } else {
        match headers.set("Set-Cookie", &format!("Username=; SameSite=None; Path=/; Httponly; Secure; Expires={}; Domain=fsotables.com;", ( Utc::now() - TimeDelta::days(28) - TimeDelta::seconds(5) ).to_rfc2822())) {  //)) {
            Ok(_) => {},
            Err(_) => {},
        }
    } /*'Username=; SameSite=None; Path=/; Httponly; Secure; Expires={}; Domain=fsotables.com;']   ( Utc::now() - TimeDelta::days(28) - TimeDelta::seconds(5) ).to_rfc2822()*/

    return headers
}

/// All of these are CODE 403
pub const ERROR_NON_MAINTAINER_ACTION: &str = "{\"Error\": \"This operation has been turned off for Mainterner level and below.\"}";
pub const ERROR_INSUFFICIENT_PERMISSISONS: &str = "{\"Error\": \"This operation is not authorizable via our API at your access level.\"}";
pub const ERROR_NOT_LOGGED_IN: &str = "{\"Error\": \"You must be logged in and provide an access token to access this endpoint.\"}";
pub const ERROR_USER_NOT_ACTIVE: &str = "{\"Error\": \"The user must be active before it can authorize this type of action\"}";

//const ERR_API_FALLBACK: &str = "{\"Error\": \"A method for this API route does not exist.\"}";

/// CODE 403
pub const ERROR_BAD_REQUEST: &str = "{\"Error\": \"Bad request, check your headers and/or JSON input.\"}";

pub async fn err_specific(e: String) -> worker::Result<Response> {
    send_failure(&e, 500).await    
}

pub async fn err_specific_and_add_report(mut external: String, internal: &String, code: u16, ctx: &RouteContext<()>) -> worker::Result<Response> {
    
    match db_insert_error_record(&internal, ctx).await {
        Ok(_) => {},
        Err(e)=> {
            
            let error_record_result = format!(",\"Addendum\": \"Also, the internal error tracker could not save this error report because of \\\'{}\\\'.  Please report!\"", e.to_string());
            let _a = external.pop();
            external += &error_record_result;
        },
    }

    send_failure(&external, code).await
}