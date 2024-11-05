use worker::*;
use serde::{Deserialize, Serialize};
use chrono::DateTime;
use crate::UserDetails;
use crate::DB_NAME;
use crate::err_specific;
use crate::JsValue;


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
    BugReports,
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
const BUG_REPORT_QUERY: &str = "SELECT * FROM bug_reports ";
const DEPRECATIONS_QUERY: &str = "SELECT * FROM deprecations "; 
const EMAIL_VALIDATIONS_QUERY: &str = "SELECT validation_id, username FROM email_validations ";
const FSO_ITEMS_QUERY: &str = "SELECT item_id, item_text, documentation, major_version, parent_id, table_id, deprecation_id, restriction_id, info_type, table_index, default_value FROM fso_items";
const FSO_TABLES_QUERY: &str = "SELECT * FROM fso_tables ";    
const PARSE_BEHAVIORS_QUERY: &str = "SELECT * FROM parse_behaviors ";    
const RESTRICTIONS_QUERY: &str = "SELECT * FROM restrictions ";    
const SESSIONS_QUERY: &str = "SELECT id, user, expiration FROM sessions ";    
const TABLE_ALIASES_QUERY: &str = "SELECT * FROM table_aliases ";    
const USERS_QUERY: &str = "SELECT id, username, role, active, email_confirmed, contribution_count, banned FROM users ";

const ACTIONS_DELETE_QUERY: &str = "DELETE FROM actions ";
const BUG_REPORT_DELETE_QUERY: &str = "DELETE FROM bug_reports ";    
const DEPRECATIONS_DELETE_QUERY: &str = "DELETE FROM deprecations "; 
const EMAIL_VALIDATIONS_DELETE_QUERY: &str = "DELETE FROM email_validations ";
const FSO_ITEMS_DELETE_QUERY: &str = "DELETE FROM fso_items";
//const FSO_TABLES_DELETE_QUERY: &str = "DELETE FROM fso_tables ";    
const PARSE_BEHAVIORS_DELETE_QUERY: &str = "DELETE FROM parse_behaviors ";    
const RESTRICTIONS_DELETE_QUERY: &str = "DELETE FROM restrictions ";    
const SESSIONS_DELETE_QUERY: &str = "DELETE FROM sessions ";    
const TABLE_ALIASES_DELETE_QUERY: &str = "DELETE FROM table_aliases ";    
//const USERS_DELETE_QUERY: &str = "DELETE FROM users ";

const ACTIONS_FILTER_ID: &str = "WHERE action_id = ?;";
const ACTIONS_FILTER_USER_ID: &str = "WHERE user_id = ?;";
const ACTIONS_FILTER_APPROVED: &str = "WHERE approved = ?;";
const ACTIONS_FILTER_USER_APPROVED_A: &str = "Where user_id = ? AND approved = ";
const ACTIONS_FILTER_USER_APPROVED_B: &str = ";";

const BUG_REPORT_FILTER: &str = "WHERE id = ?;";
const BUG_REPORT_STATUS_FILTER: &str = "WHERE status = ?;";

const DEPRECATIONS_FILTER: &str = "WHERE deprecation_id = ?;";

const EMAIL_VALIDATION_PENDING_FILTER: &str = "WHERE username = ?;";
const EMAIL_VALIDATIONS_VERIFY_FILTER: &str = "WHERE username = ?1 AND secure_key = ?2;";

const FSO_TABLES_FILTER: &str = "WHERE table_id = ?;";

const PARSE_BEHAVIORS_FILTER: &str = "WHERE behavior_id = ?;";

const RESTRICTIONS_FILTER: &str = "WHERE restriction_id = ?;";

// This may need more effort, but I wanted to try the rest first.  Also need to restrict mode zero on this one.
const SESSIONS_FILTER_A: &str = "WHERE key = \"";
const SESSIONS_FILTER_B: &str = "\" AND user = ?;";
const SESSIONS_USER_ONLY_FILTER: &str = "WHERE user = ?;";

const TABLE_ALIASES_FILTER: &str = "WHERE alias_id = ?;";

const USERS_USERNAME_FILTER: &str = "WHERE username = ?;";
const USERS_USER_ID_FILTER: &str = "WHERE id = ?;";

#[derive(Serialize, Deserialize)]
pub struct FsoTablesQueryResults {
    pub actions: Vec<Actions>,
    pub bug_reports: Vec<BugReport>,
    pub deprecations: Vec<Deprecations>,
    pub email_validations: Vec<EmailValidations>,
    pub fso_items: Vec<FsoItems>,
    pub fso_tables: Vec<FsoTables>,
    pub parse_behaviors: Vec<ParseBehavior>,
    pub restrictions: Vec<Restrictions>,
    pub users: Vec<Users>,
    pub sessions: Vec<Session>,
    pub table_aliases: Vec<TableAlias>,
}

impl FsoTablesQueryResults {
    pub async fn new_results() -> FsoTablesQueryResults{
        FsoTablesQueryResults{
            actions : Vec::new(),
            bug_reports : Vec::new(),
            deprecations : Vec::new(),
            email_validations : Vec::new(),
            fso_items : Vec::new(),
            fso_tables : Vec::new(),
            parse_behaviors : Vec::new(),
            restrictions : Vec::new(),
            users : Vec::new(),
            sessions : Vec::new(),
            table_aliases : Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Actions {
    action_id: i32,
    user_id: i32,
    action: String,
    approved_by_user: i32,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct BugReport {
    id: i32,
    user_id: i32,
    bug_type: String,
    description: String,
    status: i32,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct Deprecations {
    deprecation_id: i32,
    date: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailValidations {
    validation_id: i32,
    username: String,
}

#[derive(Serialize, Deserialize)]
pub struct FsoItems { 
    item_id: i32,
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

#[derive(Serialize, Deserialize)]
pub struct FsoTables { 
    table_id: i32,
    name: String,
    filename: String,
    modular_extension: String,
    description: String,
}

#[derive(Deserialize, Serialize)]
pub struct ParseBehavior{
    behavior_id	: i32,
    behavior : String,
    description : String,
}

#[derive(Deserialize, Serialize)]
pub struct Restrictions {
    restriction_id: i32,
    min_value: f32,
    max_value: f32,
    max_string_length:  i32,
    illegal_value_int:  i32,
    illegal_value_float:  f32,
}

#[derive(Deserialize, Serialize)]
pub struct Session {
    id: i32,
    user: String,
    expiration: String,
}

#[derive(Deserialize, Serialize)]
pub struct TableAlias {
    alias_id: i32,
    table_id: i32,
    filename: String,
}

#[derive(Deserialize, Serialize)]
pub struct Users {
    pub id: i32,
    pub username: String,
    pub role: i32,
    pub active: i32,
    pub email_confirmed: i32,
    pub contribution_count: i32,
    pub banned: i32,
}

#[derive(Serialize, Deserialize)]
struct Enabled{
    active: i32,
}

//pub async fn  db_delete_email_validation(_key: &String) -> Result<()>{
//    return Err("Not yet implemented.".to_string().into());
//}

/// Searches any table in the FSO table database
/// 
/// Mode 0 for any table is generic table dump (except for sensitive information, which is only checked against), which will not use the keys.
/// 
/// Format:
/// Table 
///  Mode Key1 Field1, Key2 Field2
/// 
/// Actions 
///  1 Action_id 
///  2 User_id 
///  3 Approved 
///  4 Key1 User_id, Key2 approved
/// 
/// Deprecations
///  1 deprecation_id
/// 
/// Email Validations 
///  1 User_id
///  2 Key1, Key2 secure_key
/// 
/// FSO Items -- Not complete TODO!!
/// 
/// FSO Tables:
///  1 table_id
/// 
/// Parse Behaviors
///  1 behavior_id
/// 
/// Restrictions
///  1 Restriction_id
/// 
/// Sessions
///  1 key1 user, key2 (session) key 
/// 
/// Table Aliases
///  1 alias_id
/// 
/// Users
///  1 user_id
///  2 username
/// 
pub async fn db_generic_search_query(table: &Table, mode: i8 , key1: &String, key2: &String, ctx: &RouteContext<()>) -> Result<FsoTablesQueryResults> {
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
                        4 => query = query + ACTIONS_FILTER_USER_APPROVED_A + key2 + ACTIONS_FILTER_USER_APPROVED_B, 
                        _ => return Err("Internal Server Error: Out of range mode in Actions generic query.".to_string().into()),
                    }
                },
                Table::BugReports => {
                    query += BUG_REPORT_QUERY; 

                    match mode {
                        0 => (),
                        1 => query += BUG_REPORT_FILTER,
                        2 => query += BUG_REPORT_STATUS_FILTER,
                        _ => return Err("Internal Server Error: Out of range mode in Deprecations generic query.".into()),
                    }
                }
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
                        // Double Binding requires special case here
                        2 => {

                            query = query + EMAIL_VALIDATIONS_VERIFY_FILTER;
                            match db.prepare(query).bind(&[JsValue::from(key1), JsValue::from(key2)]){
                                Ok(prepped_query)=> {
                                    match prepped_query.all().await {
                                        Ok(results) =>  {
                                            match results.results::<EmailValidations>(){
                                                Ok(validations) => {
                                                    let mut query_return = FsoTablesQueryResults::new_results().await;
                                                    query_return.email_validations = validations;
                                                    return Ok(query_return);
                                                },
                                                Err(e) => return Err(e),                                            
                                            }
                                        },
                                        Err(e) => return Err(e),
                                    }
                                },
                                Err(e) => return Err(e),
                            }
                        },
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
                        1 => query = query + SESSIONS_FILTER_A + key2,// + SESSIONS_FILTER_B,
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

            let bound_query : D1PreparedStatement;
            if mode == 0 {
                bound_query = db.prepare(query);
            } else {
                match db.prepare(query).bind(&[key1.into()]){
                    Ok(prepped_query)=> bound_query = prepped_query,
                    Err(e) => return Err(e),
                }
            }


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
                    Table::BugReports => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<BugReport>() {
                                    Ok(result) => {
                                        query_return.bug_reports = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },                    
                    Table::Deprecations => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<Deprecations>() {
                                    Ok(result) => {
                                        query_return.deprecations = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::EmailValidations => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<EmailValidations>() {
                                    Ok(result) => {
                                        query_return.email_validations = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::FsoItems => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<FsoItems>() {
                                    Ok(result) => {                                      
                                        query_return.fso_items = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => {
                                        return Err(e.to_string().into())},
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::FsoTables => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<FsoTables>() {
                                    Ok(result) => {
                                        query_return.fso_tables = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::ParseBehaviors => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<ParseBehavior>() {
                                    Ok(result) => {
                                        query_return.parse_behaviors = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::Restrictions => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<Restrictions>() {
                                    Ok(result) => {
                                        query_return.restrictions = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::Sessions => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<Session>() {
                                    Ok(result) => {
                                        query_return.sessions = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::TableAliases => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<TableAlias>() {
                                    Ok(result) => {
                                        query_return.table_aliases = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                    Table::Users => {
                        match bound_query.all().await {
                            Ok(results) =>{
                                match results.results::<Users>() {
                                    Ok(result) => {
                                        query_return.users = result;
                                        return Ok(query_return);
                                    },
                                    Err(e) => return Err(e),
                                }
                            },
                            Err(e)=> return Err(e),
                        }
                    },
                }                
            },
        Err(e)=> return Err(e),            
    }
}

// Email validations and sessions requires username as id to delete
pub async fn db_generic_delete(table: Table, id: &String, ctx: &RouteContext<()>) -> Result<()> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            let query: String;

            match table {
                Table::Actions => {
                    query = ACTIONS_DELETE_QUERY.to_owned() + ACTIONS_FILTER_ID;                    
                },
                Table::BugReports => {
                    query = BUG_REPORT_DELETE_QUERY.to_owned() + BUG_REPORT_FILTER;
                }
                Table::Deprecations => {
                    query = DEPRECATIONS_DELETE_QUERY.to_owned() + DEPRECATIONS_FILTER;                    
                },
                Table::EmailValidations => {
                    query = EMAIL_VALIDATIONS_DELETE_QUERY.to_owned() + EMAIL_VALIDATION_PENDING_FILTER;                    
                },
                Table::FsoItems => {
                    query = FSO_ITEMS_DELETE_QUERY.to_owned() + FSO_TABLES_FILTER;                    
                },
                Table::FsoTables => {
                    return Err("Deletion of tables not available at the api level.".to_string().into());
                },
                Table::ParseBehaviors => {
                    query = PARSE_BEHAVIORS_DELETE_QUERY.to_owned() + PARSE_BEHAVIORS_FILTER;                    
                },
                Table::Restrictions => {
                    query = RESTRICTIONS_DELETE_QUERY.to_owned() + RESTRICTIONS_FILTER;                    
                },
                Table::Sessions => {
                    query = SESSIONS_DELETE_QUERY.to_owned() + SESSIONS_USER_ONLY_FILTER;                    
                },
                Table::TableAliases => {
                    query = TABLE_ALIASES_DELETE_QUERY.to_owned() + TABLE_ALIASES_FILTER;                    
                },
                Table::Users => {
                    return Err("Deletion of users not available at the api level.".to_string().into());
                },
            }

            match db.prepare(query).bind(&[id.into()]){
                Ok(prepped_query)=> {
                    match prepped_query.run().await {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err(e),
                    }        
                },
                Err(e) => return Err(e),
            }
        },
        Err(e) => return Err(e),
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

pub async fn db_set_email_confirmed(email: &String, ctx: &RouteContext<()>) -> Result<()> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            match db.prepare("UPDATE users SET email_confirmed = 1 WHERE username = ?").bind(&[email.into()]) {
                Ok(query) => {
                    match query.run().await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(e),
                    }        
                },
                Err(e) => Err(e),
            }
        },
        Err(e) => Err(e),
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

pub async fn db_deactivate_user(email: &String, db: &D1Database) -> Result<()> {
    let query = db.prepare("UPDATE users SET active = 0 WHERE username = ?").bind(&[email.into()]).unwrap();
    
    match query.first::<UserDetails>(None).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub async fn db_activate_user(email: &String, db: &D1Database) -> Result<()> {
    let query = db.prepare("UPDATE users SET active = 1 WHERE username = ?").bind(&[email.into()]).unwrap();
    
    match query.first::<UserDetails>(None).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
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

pub async fn db_set_new_pass(email: &String, password: &String, ctx: &RouteContext<()>) -> Result<()> {
    let db = ctx.env.d1(DB_NAME);

    match &db{
        Ok(connection) => {
            let query_string = format!("UPDATE users SET password = \"{}\", email_confirmed = 1 WHERE username = ?", password);

            let query = connection.prepare(&query_string).bind(&[email.into()]).unwrap();
            
            match query.first::<UserDetails>(None).await {
                Ok(_) => Ok(()),
                Err(e) => return Err(e.to_string().into()),
            }
        },
        Err(e) => return Err(e.to_string().into()),
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


pub async fn db_session_add(token: &String, email: &String, time: &String, ctx: &RouteContext<()>) -> worker::Result<()> {

    // METACOMMENT! The below didn't end up working.  I did trick the JsValue constructor to use the 
    // vector, but the database code said, "MUAAAAAH I CAN'T USE AN OBJECT!!!!" In any case, back to regular comments...
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

    let db = ctx.env.d1(DB_NAME);

    match &db{
        Ok(connection)=> {

            // So we'll just use the work around .... again... until I can find a way to bind more than one item.
            let final_token = &token.replace("\"", "");
            let query = format!("INSERT INTO sessions (key, user, expiration) VALUES (\"{}\", ?, \"{}\")", final_token, time);

            match connection.prepare(query).bind(&[email.into()]) {
                Ok(statement) => {
                    match statement.run().await {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err(e),
                    }
                },
                Err(e)=> return Err(e),
            }
        },
        Err(e) => return Err(e.to_string().into()),
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
                            if results.is_empty() {
                                return Ok(false);
                            }
                            match results[0].expiration.parse::<DateTime<chrono::Utc>>(){
                                Ok(session_time) => { return Ok(time.parse::<DateTime<chrono::Utc>>().unwrap() < session_time); },
                                Err(_) => return Ok(false),
                            }
                        },
                        Err(_) => return Ok(false),        
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