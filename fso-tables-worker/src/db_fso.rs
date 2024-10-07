use worker::*;
use serde::{Deserialize, Serialize};
use crate::UserDetails;
use crate::DB_NAME;
use crate::err_specific;
use chrono::DateTime;
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
    Actions,
    Deprecations,
    EmailValidations, 
    FsoItems,
    FsoTables,
    ParseBehaviors,
    Restrictions,
    Sessions,
    TableAliases,
    Users,
}

const ACTIONS_QUERY: &str = "SELECT * FROM actions ";    
const DEPRECATIONS_QUERY: &str = "SELECT * FROM deprecations "; 
const EMAIL_VALIDATIONS_QUERY: &str = "SELECT validation_id, user_id FROM email_validations ";
const FSO_ITEMS_QUERY: &str = "SELECT * FROM fso_items ";
const FSO_TABLES_QUERY: &str = "SELECT * FROM fso_tables ";    
const PARSE_BEHAVIORS_QUERY: &str = "SELECT * FROM parse_behaviors ";    
const RESTRICTIONS_QUERY: &str = "SELECT * FROM restrictions ";    
const SESSIONS_QUERY: &str = "SELECT id, user, expiration,  FROM sessions ";    
const TABLE_ALIASES_QUERY: &str = "SELECT * FROM table_aliases ";    
const USERS_QUERY: &str = "SELECT id, username, role, active, email_confirmed, contribution_count, banned FROM users ";

const ACTIONS_FILTER_ID: &str = "WHERE action_id = ?;";
const ACTIONS_FILTER_USER_ID: &str = "WHERE user_id = ?;";
const ACTIONS_FILTER_APPROVED: &str = "WHERE approved = ?;";
const ACTIONS_FILTER_USER_APPROVED: &str = "Where user_id = ? AND approved = {};";

const DEPRECATIONS_FILTER: &str = "WHERE deprecation_id = ?;";

const EMAIL_VALIDATION_PENDING_FILTER: &str = "WHERE user_id = ?;";
const EMAIL_VALIDATIONS_VERIFY_FILTER: &str = "WHERE user_id = ? AND secure_key = {};";

const FSO_TABLES_FILTER: &str = "WHERE table_id = ?;";

const PARSE_BEHAVIORS_FILTER: &str = "WHERE behavior_id = ?;";

const RESTRICTIONS_FILTER: &str = "WHERE restriction_id = ?;";

// This may need more effort, but I wanted to try the rest first.  Also need to restrict mode zero on this one.
const SESSIONS_FILTER_A: &str = "WHERE key = {";
const SESSIONS_FILTER_B: &str = " AND user = ?;";

const TABLE_ALIASES_FILTER: &str = "WHERE alias_id = ?;";

const USERS_USERNAME_FILTER: &str = "WHERE username = ?;";
const USERS_USER_ID_FILTER: &str = "WHERE user_id = ?;";

struct FsoTablesQueryResults {
    actions: Vec<Actions>,
    deprecations: Vec<Deprecations>,
    email_validations: Vec<EmailValidations>,
    fso_items: Vec<FsoItems>,
    fso_tables: Vec<FsoTables>,
    parse_behaviors: Vec<ParseBehavior>,
    restrictions: Vec<Restrictions>,
    users: Vec<Users>,
    session: Vec<Users>,
}

impl FsoTablesQueryResults {
    async fn new_results() -> FsoTablesQueryResults{
        FsoTablesQueryResults{
            actions : Vec::new(),
            deprecations : Vec::new(),
            email_validations : Vec::new(),
            fso_items : Vec::new(),
            fso_tables : Vec::new(),
            parse_behaviors : Vec::new(),
            restrictions : Vec::new(),
            users : Vec::new(),
            session : Vec::new(),
        }
    }
}

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
    banned: i32,
}

#[derive(Deserialize, Serialize)]
struct Session {
    id: i32,
    user: String,
    expiration: String,
}

#[derive(Serialize, Deserialize)]
struct Enabled{
    active: i32,
}

pub async fn db_generic_query(table: &Table, mode: i8 , key1: &String, key2: &String, key3: &String, ctx: &RouteContext<()>) -> Result<FsoTablesQueryResults> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            let mut query = "".to_string();

            match table {
                Table::Actions => {
                    query += ACTIONS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += ACTIONS_FILTER_ID,
                        2 => query += ACTIONS_FILTER_USER_ID,
                        3 => query += ACTIONS_FILTER_APPROVED,
                        4 => query += ACTIONS_FILTER_USER_APPROVED, 
                        _ => return Err("Internal Server Error: Out of range mode in Actions generic query.".to_string().into()),
                    }
                },
                Table::Deprecations => {
                    query += DEPRECATIONS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += DEPRECATIONS_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Deprecations generic query.".into()),
                    }

                },
                Table::EmailValidations => {
                    query += EMAIL_VALIDATIONS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += EMAIL_VALIDATION_PENDING_FILTER,
                        2 => query += EMAIL_VALIDATIONS_VERIFY_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Email Validations generic query.".into()),
                    }

                }, 
                // This is definitely not done.  Figuring out all the relevant stuff for FSO items is a lot of effort.
                Table::FsoItems => {
                    query += FSO_ITEMS_QUERY; 

                    match mode {
                        0 => (),
                        _ => return Err("Internal Server Error: Out of range mode in FSO_ITEMS generic query.".into()),
                    }

                },
                Table::FsoTables => {
                    query += FSO_TABLES_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += FSO_TABLES_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in FSO_Tables generic query.".into()),
                    }

                },
                Table::ParseBehaviors => {
                    query += PARSE_BEHAVIORS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += PARSE_BEHAVIORS_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Parse Behaviors generic query.".into()),
                    }

                },
                Table::Restrictions => {
                    query += RESTRICTIONS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += RESTRICTIONS_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Restrictions generic query.".into()),
                    }

                },
                Table::Sessions => {
                    query += SESSIONS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += SESSIONS_FILTER_A,
                        _ => return Err("Internal Server Error: Out of range mode in Sessions generic query.".into()),
                    }

                },
                Table::TableAliases => {
                    query += TABLE_ALIASES_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += TABLE_ALIASES_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Table Aliases generic query.".into()),
                    }

                },
                Table::Users => {
                    query += USERS_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += USERS_USER_ID_FILTER,
                        2 => query += USERS_USERNAME_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Usernames generic query.".into()),
                    }

                },
            }

            let mut query_return = FsoTablesQueryResults::new_results().await;

            match db.prepare(query).bind(&[key1.into()]) {
                Ok(bound_query) => {
                    match table {
                        Table::Actions => {
                            match bound_query.all().await {
                                Ok(results) =>{
                                    match results.results::<Actions>() {
                                        Ok(result) => {
                                            query_return.actions = result;
                                            return Ok(query_return);
                                        },
                                        Err(e) => return Err(e),
                                    }
                                },
                                Err(e)=> return Err(e),
                            }
                        },
                    
                        Table::Deprecations => {},
                        Table::EmailValidations => {},
                        Table::FsoItems => {},
                        Table::FsoTables => {},
                        Table::ParseBehaviors => {},
                        Table::Restrictions => {},
                        Table::Sessions => {},
                        Table::TableAliases => {},
                        Table::Users => {},
                    }
                    return Err("Not yet implemented.".to_string().into());        
                },
                Err(e) => return Err(e.into()),            
            }
        },
        Err(e) => return Err(e.into()),
    }
}

 
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
    let query = SESSIONS_QUERY.to_owned() + &SESSIONS_FILTER_A + &format!("{}", final_token) + &SESSIONS_FILTER_B;

    match db.prepare(query).bind(&[username.into()]) {
        Ok(statement) => {
            match statement.run().await {
                Ok(result) =>
                    match result.results::<Session>() {
                        Ok(results) => { 
                            match results[0].expiration.parse::<DateTime<chrono::Utc>>(){
                                Ok(session_time) => return Ok(time.parse::<DateTime<chrono::Utc>>().unwrap() < session_time),
                                // TODO! Once we know this function works, two of these call need to be changed into Ok(false)
                                Err(e) => return Err(e.to_string().into()),
                            }
                        },
                        Err(e) => return Err(e),        
                    },
                Err(e)=> Err(e),
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