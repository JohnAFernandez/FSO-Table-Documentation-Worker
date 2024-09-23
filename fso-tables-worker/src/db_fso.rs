use worker::*;
use serde::{Deserialize, Serialize};
use crate::UserDetails;
use crate::DB_NAME;
use crate::err_specific;
use chrono::{TimeDelta, DateTime};
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

pub enum Table {
    ACTIONS,
    DEPRECATIONS,
    EMAIL_VALIDATIONS, 
    FSO_ITEMS,
    FSO_TABLES,
    PARSE_BEHAVIORS,
    RESTRICTIONS,
    SESSIONS,
    TABLE_ALIASES,
    USERS,
}

const ActionsQuery: &str = "SELECT * FROM actions ";    
const DeprecationsQuery: &str = "SELECT * FROM deprecations "; 
const EmailValidationsQuery: &str = "SELECT validation_id, user_id FROM email_validations ";
const FsoItemsQuery: &str = "SELECT * FROM fso_items ";
const FsoTablesQuery: &str = "SELECT * FROM fso_tables ";    
const ParseBehaviorsQuery: &str = "SELECT * FROM parse_behaviors ";    
const RestrictionsQuery: &str = "SELECT * FROM restrictions ";    
const SessionsQuery: &str = "SELECT id, user, expiration,  FROM sessions ";    
const TableAliasesQuery: &str = "SELECT * FROM table_aliases ";    
const UsersQuery: &str = "SELECT id, username, role, active, email_confirmed, contribution_count FROM users ";

const ActionsFilterId: &str = "WHERE action_id = ?";
const ActionsFilterUserId: &str = "WHERE user_id = ?";
const ActionsFilterApproved: &str = "WHERE approved = ?";
const ActionsFilterUserApproved: &str = "Where user_id = ? AND approved = {}";

const SessionsFilter: &str = "WHERE key = {} AND user = ?;";



#[derive(Serialize, Deserialize)]
struct Actions {
    action_id: i32,
    user_id: i32,
    action: String,
    approved_by_user: i32,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
struct Deprecations {
    deprecation_id: i32,
    date: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
struct EmailValidations {
    validation_id: i32,
    user_id: i32,
}

#[derive(Serialize, Deserialize)]
struct FsoItems { 
    item_id: i32,
    item_text: String,
    documentation: String,
    major_version: i32,
    parent_id: i32,
    table_id: i32,
    deprecation_id: i32,
    restriction_id: i32,
    info_type: String,
    table_index: i32,
    default_value: String,
}

#[derive(Serialize, Deserialize)]
struct FsoTables { 
    table_id: i32,
    name: String,
    filename: String,
    modular_extension: String,
    description: String,
}

#[derive(Deserialize, Serialize)]
struct ParseBehavior{
    behavior_id	: i32,
    behavior : String,
    description : String,
}

#[derive(Deserialize, Serialize)]
struct Restrictions {
    restriction_id: i32,
    min_value: f32,
    max_value: f32,
    max_string_length:  i32,
    illegal_value_int:  i32,
    illegal_value_float:  f32,
}

#[derive(Deserialize, Serialize)]
struct Users {
    id: i32,
    username: String,
    role: i32,
    active: i32,
    email_confirmed: i32,
    contribution_count: i32,
} // TODO!  I need a banned button.

struct Session {
    id: i32,
    user: String,
    expiration: String,
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


pub async fn db_check_token(username: &String, token: &String, time: String, db: &D1Database) -> Result<bool> {
    let final_token = &token.replace("\"", "");
    let query = format!(SessionsQuery + SessionsFilter, final_token);

    match db.prepare(query).bind(&[username.into()]) {
        Ok(statement) => {
            match statement.run().await.results::<Session>() {
                Ok(results) => { 
                    match results.expiration.parse::<DateTime<Utc>>(){
                        Ok(session_time) => return Ok(time.parse::<DateTime<Utc>>().unwrap() < session_time),
                        // TODO! Once we know this function works, two of these call need to be changed into Ok(false)
                        Err(e) => return Err(e),
                    }
                },
                Err(e) => return Err(e),
            }
        },
        Err(e)=> return Err(e),
    }
}

// How to compare timestamps
/*

fn main() {
    let a = Utc::now();
    let b = Utc::now() + TimeDelta::hours(2);
    
    let diff = b - a;
    
    print!("{}", diff.to_string());

    if a < b {
        print!("\nTrue!");
    } else {
        print!("\nFalse!");
    }
    
    let aString = a.to_string();
    let bString = b.to_string();
    
    print!("\n{}", aString);
    print!("\n{}", bString);
    let date_str = aString.parse::<DateTime<Utc>>().unwrap();

    print!("\n{}", date_str.to_string());
} */