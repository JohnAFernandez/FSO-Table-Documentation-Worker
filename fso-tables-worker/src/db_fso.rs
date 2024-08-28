use worker::*;
use serde::{Deserialize, Serialize};
use crate::UserDetails;
use crate::DB_NAME;
use crate::err_specific;
//use wasm_bindgen::JsValue;

#[derive(PartialEq, PartialOrd)]
pub enum UserRole {
    OWNER = 0,
    ADMIN = 1, // Able to upgrade other users to a maintainer or downgrade maintainers to viewers
    MAINTAINER = 2, // Able to make changes to table fsdocs
    VIEWER = 3, // Waiting for someone to approve an upgrade to a maintainer level
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

#[derive(Deserialize, Serialize)]
struct BasicCount {
    the_count: i32,
}

#[derive(Deserialize,Serialize)]
struct Active {
    active: i32,
}

#[derive(Deserialize, Serialize)]
struct GeneralResults{
    rows : Vec<Vec<String>>,
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

pub async fn db_force_role(email: &String, db : &D1Database, role: UserRole) -> worker::Result<()> {
    let role_num : i32;
    
    match role {
        UserRole::ADMIN => role_num = 1,
        UserRole::MAINTAINER => role_num = 2,
        UserRole::VIEWER => role_num = 3,
        UserRole::OWNER => return Err("Nice try bro.  No owners unless I add them directly.".into()),
    }

    let query_string = format!("UPDATE users SET role = {} WHERE username = ?", role_num);

    let query = db.prepare(query_string).bind(&[email.into()]).unwrap();

    match query.first::<UserDetails>(None).await {
        Ok(_) => Ok(()),
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

pub async fn db_activate_user(email: &String, db: &D1Database) {
    let query = db.prepare("UPDATE users SET active = 1 WHERE username = ?").bind(&[email.into()]).unwrap();
    
    match query.first::<UserDetails>(None).await {
        Ok(_) => (),
        Err(e) => panic!("{}", e.to_string()),
    }
}

pub async fn db_user_is_active(email: &String, db: &D1Database) -> bool {
    let query = db.prepare("SELECT active FROM users WHERE username = ? LIMIT 1").bind(&[email.into()]).unwrap();

    match query.first::<Active>(None).await {
        Ok(status) => {
            match status {
                Some(active) => {
                    if active.active == 1{
                        return true
                    } else {
                        return false
                    }
                },
                None => return false,
            }
        },
        Err(_) => return false,
    }
}

pub async fn db_check_password(email: &String, password: &String, db: &D1Database) -> bool {
    let query_string = format!("SELECT count(*) AS the_count FROM users WHERE username = ? and password = \"{}\"", password);
    let query = db.prepare(&query_string).bind(&[email.into()]).unwrap();

    match query.first::<BasicCount>(None).await {
        Ok(count) => {
            match count {
                Some(count) => {
                    if count.the_count > 0 {
                        return true
                    } else {
                        return false
                    }
                },
                None => return false,
            }
        },
        Err(_) => return false,
    }    
}

pub async fn db_set_new_pass(email: &String, password: &String, db: &D1Database) -> String {
    let query_string = format!("UPDATE users SET password = \"{}\" WHERE username = ?", password);

    let query = db.prepare(&query_string).bind(&[email.into()]).unwrap();
    
    match query.first::<UserDetails>(None).await {
        Ok(_) => return "Success!".to_string(),
        Err(e) => return e.to_string(),
    }
}

pub async fn db_user_stats_get(_: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {   
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

#[derive(Deserialize, Serialize)]
struct ParseBehavior{
    behavior_id	: i32,
    behavior : String,
    description : String,
}

pub async fn db_get_parse_behavior_types(db : &D1Database) -> worker::Result<Response>{
    let query = db.prepare("SELECT * FROM parse_behaviors;");

    match query.all().await {
        Ok(results) => {
            match results.results::<ParseBehavior>() {
                Ok(result) => return Response::from_json(&result),
                Err(e) => return err_specific(e.to_string()).await,
            }
        },
        Err(e) => return err_specific(e.to_string()).await,
    }    
}


pub async fn db_session_add(token: &String, email: &String, time: &String, db : &D1Database) -> worker::Result<()> {

    // METACOMMENT! The below didn't end up working.  I did trick the JsValue constructor to use the 
    // vector, but the database code said, "MUAAAAAH I CAN'T USE AN OBJECT!!!!"
    // It may not be possible, but I think I have to trick it to create an array object.
    // I'm just not sure how.
    
    // I know this is silly, but JsValue constructors can't accept vectors of Strings
    // Only vectors of numeric types (although I haven't tried it myself)
    // Anyway ... this logic is only temporary.  I should be able to create a function that does this
    // for any input.
    /*let js_value = JsValue::from(token);
    let js_value2 = JsValue::from(email);
    let js_value3 = JsValue::from(time);

    let input_vec = vec!{js_value, js_value2, js_value3};
    let js_value2 = JsValue::from(input_vec);
    */

    // So we'll just use the work around .... again... until I can find a way to bind more than one item.
    let final_token = &token.replace("\"", "");
    let query = format!("INSERT INTO sessions (key, user, expiration) VALUES (\"{}\", ?, \"{}\")", final_token, time);

    match db.prepare(query).bind(&[email.into()]) {
        Ok(statement) => {
            match statement.run().await {
                Ok(_) => return Ok(()),
                Err(e) => return Err(e),
            }
        },
        Err(e)=> return Err(e),
    }
}