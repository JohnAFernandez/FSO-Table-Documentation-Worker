use worker::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, TimeDelta};
use crate::{UserDetails, DB_NAME, err_specific, JsValue, DB_TIME_FORMAT, NewItem, get_current_time_i64};
use is_number::{is_integer};
use serde_json::from_str;

#[derive(PartialEq, PartialOrd)]
pub enum UserRole {
    OWNER = 0,
    ADMIN = 1, // Able to upgrade other users to a maintainer or downgrade maintainers to viewers
    MAINTAINER = 2, // Able to make changes to table fsdocs
    VIEWER = 3, // Waiting for someone to approve an upgrade to a maintainer level
}

const DUMMY_FLOAT : f64 = 9191.919;
const DUMMY_INT : i32 = -2147483647;

pub async fn number_to_role(n: i64) -> worker::Result<UserRole> {
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
//    Sessions,
    TableAliases,
    Users,
}

const ACTIONS_QUERY: &str = "SELECT * FROM actions ";    
const BUG_REPORT_QUERY: &str = "SELECT * FROM bug_reports ";
const DEPRECATIONS_QUERY: &str = "SELECT * FROM deprecations "; 
const EMAIL_VALIDATIONS_QUERY: &str = "SELECT validation_id, username, expires FROM email_validations ";
const FSO_ITEMS_QUERY: &str = "SELECT item_id, item_text, documentation, major_version, parent_id, table_id, deprecation_id, restriction_id, info_type, table_index, default_value FROM fso_items ";
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
//const SESSIONS_DELETE_QUERY: &str = "DELETE FROM sessions ";    
const TABLE_ALIASES_DELETE_QUERY: &str = "DELETE FROM table_aliases ";    
//const USERS_DELETE_QUERY: &str = "DELETE FROM users ";

// Some (maybe most) of these will end up being unused as specialized functions are already written.  
const ACTIONS_INSERT_QUERY: &str = "INSERT INTO actions (user_id, action, approved_by_user, timestamp, route, item_index, approved) VALUES (?1, ?2, ?3, ";
const ACTIONS_INSERT_QUERY_2: &str = ", ?4, ?5, ?6)";

//const BUG_REPORT_INSERT_QUERY: &str = "INSERT INTO bug_reports ( user_id, bug_type, description, status, timestamp) VALUES (?1, ?2, ?3, ?4, ";    
//const BUG_REPORT_INSERT_QUERY_2: &str = ");";    

const DEPRECATIONS_INSERT_QUERY: &str = "INSERT INTO deprecations (version, description, partial, item_id) VALUES (?1, ?2, ?3, ?4)"; 
//const EMAIL_VALIDATIONS_INSERT_QUERY: &str = "INSERT INTO email_validations (username) VALUES (?1)";
const ERROR_REPORT_INSERT_QUERY: &str = "INSERT INTO error_reports (error, timestamp) VALUES (?1, ";
const ERROR_REPORT_INSERT_QUERY_2: &str = ");";
const FSO_ITEMS_INSERT_QUERY: &str = "INSERT INTO fso_items (item_text, documentation, major_version, parent_id, table_id, deprecation_id, restriction_id, info_type, table_index, default_value) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
//const FSO_TABLES_INSERT_QUERY: &str = "INSERT INTO fso_tables VALUES (?1, ?2)";    
//const PARSE_BEHAVIORS_INSERT_QUERY: &str = "INSERT INTO parse_behaviors (behavior, description) VALUES (?1, ?2)";

// restrictions are special.  The values that are important vary between row.  So we need to have dummy values that will never ever be used, and this cannot be defined outside a function.
// const RESTRICTIONS_INSERT_QUERY: &str = ;    
//const SESSIONS_INSERT_QUERY: &str = "INSERT INTO sessions (user, expiration) VALUES (?1, ";
//const SESSIONS_INSERT_QUERY_2: &str = " );";
//const TABLE_ALIASES_INSERT_QUERY: &str = "INSERT INTO table_aliases (table_id, filename) VALUES (?1, ?2)";    
//const USERS_INSERT_QUERY: &str = "INSERT INTO users ( username, role, active, email_confirmed, contribution_count, banned: i64) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

// Other patches should be done on the database end.
const ACTIONS_PATCH_APPROVED_QUERY: &str = "UPDATE actions SET approved = 1, approved_by_user = ?1;";

const BUG_REPORT_PATCH_APPROVED_QUERY: &str = "UPDATE bug_reports SET approved_by_user = ?1 ";
const BUG_REPORT_PATCH_BUGTYPE_QUERY: &str = "UPDATE bug_reports SET bug_type = ?1 ";
const BUG_REPORT_PATCH_DESCRIPTION_QUERY: &str = "UPDATE bug_reports SET description = ?1 ";
const BUG_REPORT_PATCH_STATUS_QUERY: &str = "UPDATE bug_reports SET status = ?1 ";

const DEPRECATIONS_PATCH_VERSION_QUERY: &str = "UPDATE deprecations SET version = ?1 ";
const DEPRECATIONS_PATCH_DESCRIPTION_QUERY: &str = "UPDATE deprecations SET description = ?1 ";
const DEPRECATIONS_PATCH_PARTIAL_QUERY: &str = "UPDATE deprecations SET partial = ?1";


//No email validations updates if something is wrong with one of those it has to be done on the database side

const FSO_ITEM_PATCH_STRINGS : [&str; 8] = [
    "UPDATE fso_items SET default_value = ?1 ", 
    "UPDATE fso_items SET documentation = ?1 ",
    "UPDATE fso_items SET info_type = ?1 ",
    "UPDATE fso_items SET item_text = ?1 ",
    "UPDATE fso_items SET major_version = ?1 ",
    "UPDATE fso_items SET parent_id = ?1 ",
    "UPDATE fso_items SET table_id = ?1 ",
    "UPDATE fso_items SET table_index = ?1 "
    ]; 

// Table Patching to be done by direct editng.

const PARSE_BEHAVIORS_PATCH_BEHAVIOR_QUERY: &str = "UPDATE parse_behaviors SET behavior = ?1 ";
const PARSE_BEHAVIORS_PATCH_DESCRIPTION_QUERY: &str = "UPDATE parse_behaviors SET description = ?1 ";

const RESTRICTIONS_PATCH_MIN_VALUE_QUERY: &str = "UPDATE restrictions SET min_value = ?1 ";
const RESTRICTIONS_PATCH_MAX_VALUE_QUERY: &str = "UPDATE restrictions SET max_value = ?1 ";
const RESTRICTIONS_PATCH_MAX_STRING_LENGTH_QUERY: &str = "UPDATE restrictions SET max_string_length = ?1 ";
const RESTRICTIONS_PATCH_ILLEGAL_VALUE_INT_QUERY: &str = "UPDATE restrictions SET illegal_value_int = ?1 ";
const RESTRICTIONS_PATCH_ILLEGAL_VALUE_FLOAT_QUERY: &str = "UPDATE restrictions SET illegal_value_float = ?1 ";
const RESTRICTIONS_PATCH_ALLOWED_VALUES_QUERY: &str = "UPDATE restrictions SET allowed_values = ?1";

//const SESSIONS_PATCH_EXPIRATION_QUERY: &str =  "UPDATE sessions SET expiration = ?1 ";  

const TABLE_ALIASES_PATCH_TABLE_ID_QUERY: &str = "UPDATE table_aliases SET table_id = ?1 ";
const TABLE_ALIASES_PATCH_FILENAME_QUERY: &str = "UPDATE table_aliases SET filename = ?1 ";


const BINDABLE_ACTIONS_FILTER_ID: &str = "WHERE action_id = ?;";
const BINDABLE_ACTIONS_FILTER_BY_ID: &str = "WHERE action_id = ?2;";
const ACTIONS_FILTER_USER_ID: &str = "WHERE user_id = ?;";
const ACTIONS_FILTER_APPROVED: &str = "WHERE approved = ?;";
const ACTIONS_FILTER_USER_APPROVED_A: &str = "Where user_id = ? AND approved = ";
const ACTIONS_FILTER_USER_APPROVED_B: &str = ";";
const ACTIONS_FILTER_TIMESTAMP: &str = "WHERE timestamp = ?;";

const BUG_REPORT_FILTER: &str = "WHERE id = ?;";
const BUG_REPORT_FILTER_BINDABLE: &str = "WHERE id = ?2;";
const BUG_REPORT_STATUS_FILTER: &str = "WHERE status = ?;";

const DEPRECATIONS_FILTER: &str = "WHERE deprecation_id = ?;";
const DEPRECATIONS_FILTER_BINDABLE: &str = "WHERE deprecation_id = ?2;";

const EMAIL_VALIDATION_PENDING_FILTER: &str = "WHERE username = ?;";
//const EMAIL_VALIDATION_PENDING_FILTER_BINDABLE: &str = "WHERE username = ?2;";
const EMAIL_VALIDATIONS_VERIFY_FILTER: &str = "WHERE username = ?1 AND secure_key = ?2;";

const FSO_ITEMS_TABLE_FILTER: &str = "WHERE table_id = ?";
const FSO_ITEMS_TABLE_AND_NAME_FILTER: &str = "WHERE table_id = ?1 AND item_text = ?2 AND parent_id = ?3";
const BINDABLE_FSO_ITEMS_FILTER_: &str = "WHERE item_id = ?2";

const FSO_TABLES_FILTER: &str = "WHERE table_id = ?;";
//const FSO_TABLES_FILTER_BINDABLE: &str = "WHERE table_id = ?2;";

const PARSE_BEHAVIORS_FILTER: &str = "WHERE behavior_id = ?;";
const PARSE_BEHAVIORS_FILTER_BINDABLE: &str = "WHERE behavior_id = ?2;";

const RESTRICTIONS_FILTER: &str = "WHERE restriction_id = ?;";
const RESTRICTIONS_FILTER_BINDABLE: &str = "WHERE restriction_id = ?2;";

// This may need more effort, but I wanted to try the rest first.  Also need to restrict mode zero on this one.
const SESSIONS_FILTER_A: &str = "WHERE key = \"";
const SESSIONS_FILTER_B: &str = "\" AND user = ?;";
//const SESSIONS_FILTER_USER_BINDABLE: &str = "WHERE user = ?2;";
//const SESSIONS_USER_ONLY_FILTER: &str = "WHERE user = ?;";

const TABLE_ALIASES_FILTER: &str = "WHERE alias_id = ?;";
const TABLE_ALIASES_FILTER_BINDABLE: &str = "WHERE alias_id = ?2;";

const USERS_USERNAME_FILTER: &str = "WHERE username = ?;";
const USERS_USER_ID_FILTER: &str = "WHERE id = ?;";
//const USERS_USER_ID_FILTER_BINDABLE: &str = "WHERE id = ?2;";

const ERROR_HELPER: &str = " discovered using the query: ";

#[derive(Serialize, Deserialize)]
pub struct FsoTablesQueryResults {
    pub actions: Vec<ActionsInternal>,
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
pub struct ActionsInternal {
    pub action_id: i32,
    pub user_id: i32,
    pub approved_by_user: i32,
    pub timestamp: i64,
    pub route: String,
    pub item_index: i32,
    pub approved: i32,
    pub action: String,
}

impl ActionsInternal {
    pub async fn new_action_internal(user: i32, action_string: String, approving_user: i32, the_timestamp: i64, is_approved: bool, the_route: String, the_item_index: i32) -> ActionsInternal{
        let approved_proxy: i32;

        if is_approved {
            approved_proxy = 1;
        } else {
            approved_proxy = 0;
        }

        ActionsInternal{
            action_id: -1,
            user_id: user,
            action: action_string,
            approved_by_user: approving_user,
            timestamp: the_timestamp,
            approved: approved_proxy,
            route: the_route,
            item_index: the_item_index,
        }
    }
}

#[derive(Serialize, Deserialize)] // Should only need to serialize, since this isn't postable via API
pub struct ActionsExternal {
    pub action_id: i32,
    pub user: String,
    pub action: String,
    pub approved_by_user: String,
    pub timestamp: String,
    pub item_index: i32,
    pub approved: i32,
    pub route: String,
}

#[derive(Serialize, Deserialize)]
pub struct BugReport {
    pub id: i32,
    pub user_id: i32,
    pub bug_type: String,
    pub description: String,
    pub status: i32,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Deprecations {
    pub deprecation_id: i32,
    pub version: String,
    pub description: String,
    pub partial: i32,
    pub item_id: i32,
}

#[derive(Serialize, Deserialize)]
pub struct DeprecationNew {
    pub version: String,
    pub description: String,
    pub partial: i32,
    pub item_id: i32,
}

#[derive(Serialize, Deserialize)]
pub struct DeprecationIn {
    pub deprecation_id: i32,
    pub version: String,
    pub description: String,
    pub partial: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailValidations {
    validation_id: i32,
    username: String,
    pub expires: i64,
}

#[derive(Serialize, Deserialize)]
pub struct FsoItems { 
    pub item_id: i32,
    pub item_text: String,
    pub documentation: String,
    pub major_version: String,
    pub parent_id: i32,
    pub table_id: i32,
    pub deprecation_id: i32,
    pub restriction_id: i32,
    pub info_type: String,
    pub table_index: i32,
    pub default_value: String,
}

#[derive(Deserialize)]
pub struct FsoItemsPatch { 
    pub item_id: i32,
    pub item_text: String,
    pub documentation: String,
    pub major_version: String,
    pub parent_id: String,
    pub table_id: String,
    pub deprecation_id: String,
    pub restriction_id: String,
    pub info_type: String,
    pub table_index: String,
    pub default_value: String,
}


#[derive(Serialize, Deserialize)]
pub struct FsoTables { 
    pub table_id: i32,
    pub name: String,
    pub filename: String,
    pub modular_extension: String,
    pub description: String,
}

#[derive(Deserialize, Serialize)]
pub struct ParseBehavior{
    pub behavior_id	: i32,
    pub behavior : String,
    pub description : String,
}

#[derive(Deserialize, Serialize)]
pub struct Restrictions {
    pub restriction_id: i64,
    pub min_value: f32,
    pub max_value: f32,
    pub max_string_length:  i32,
    pub illegal_value_int:  i32,
    pub illegal_value_float:  f32,
}

// 0 min_value, 1 Max_value, 2 max string length, 3 illegal value int, 4 illegal value float, 5 min and max int, 6 min and max float, 7 value list
pub struct RestrictionNew {
    pub type_of: i32,
    pub int_value1: i32,
    pub int_value2: i32,
    pub float_value1: String,
    pub float_value2: String,
    pub allowed_value_list: String,
}

#[derive(Deserialize, Serialize)]
pub struct Session {
    id: i64,
    user: String,
    expiration: i64,
}

#[derive(Deserialize, Serialize)]
pub struct TableAlias {
    pub alias_id: i32,
    pub table_id: i32,
    pub filename: String,
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

pub async fn db_prepare_query_error(e: Error, query: String) -> String {
    return e.to_string() + ERROR_HELPER + &query;
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
pub async fn db_generic_search_query_ctx(table: &Table, mode: i8 , key1: &String, key2: &String, key3: &String, ctx: &RouteContext<()>) -> Result<FsoTablesQueryResults> {
    match ctx.d1(DB_NAME){
        Ok(db) => db_generic_search_query_db(table, mode, key1, key2, key3, &db).await,
        Err(e) => return Err(e),
    }
}

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
pub async fn db_generic_search_query_db(table: &Table, mode: i8 , key1: &String, key2: &String, key3: &String, db: &D1Database) -> Result<FsoTablesQueryResults> {
    let mut query = "".to_string();
    let mut integer_key= false;

    match table {
        Table::Actions => {
            query += ACTIONS_QUERY; 

            match mode {
                0 => (),
                1 => { query += BINDABLE_ACTIONS_FILTER_ID;
                    integer_key = true;
                }
                2 => { query += ACTIONS_FILTER_USER_ID;
                    integer_key = true;
                }
                3 => {query += ACTIONS_FILTER_APPROVED;
                    integer_key = true;
                },
                4 => {query += &(ACTIONS_FILTER_USER_APPROVED_A.to_owned() + key2 + ACTIONS_FILTER_USER_APPROVED_B);
                    integer_key= true;
                }, 
                5 => query += ACTIONS_FILTER_TIMESTAMP,
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Actions generic query.", mode).to_string().into()),
            }
        },
        Table::BugReports => {
            query += BUG_REPORT_QUERY; 

            match mode {
                0 => (),
                1 => {query += BUG_REPORT_FILTER;
                    integer_key = true;
                },
                2 => {query += BUG_REPORT_STATUS_FILTER;
                    integer_key = true;
                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Bug Report generic query.", mode).to_string().into()),
            }
        }
        Table::Deprecations => {
            query += DEPRECATIONS_QUERY; 

            match mode {
                0 => (),
                1 => { query += DEPRECATIONS_FILTER;
                    integer_key = true;
                },
                    _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Deprecations generic query.", mode).to_string().into()),
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
                    match db.prepare(query.clone()).bind(&[JsValue::from(key1), JsValue::from(key2)]){
                        Ok(prepped_query)=> {
                            match prepped_query.all().await {
                                Ok(results) =>  {
                                    //return Err(format!("{{\"Error\":\"TESTING, checkpoint 3 reached! on mode 2 key 1 {} key 2 {} query {} \"}}", key1, key2, query.to_string()).into());

                                    match results.results::<EmailValidations>(){
                                        Ok(validations) => {
                                            let mut query_return = FsoTablesQueryResults::new_results().await;
                                            query_return.email_validations = validations;
                                            return Ok(query_return);
                                        },
                                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),                                            
                                    }
                                },
                                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                            }
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Email Validations generic query.", mode).to_string().into()),
            }

        }, 
        // This is definitely not done.  Figuring out all the relevant stuff for FSO items is a lot of effort.
        Table::FsoItems => {
            query += FSO_ITEMS_QUERY; 

            match mode {
                0 => (),
                1 => { query += FSO_ITEMS_TABLE_FILTER;
                    integer_key = true;
                },
                2 => { 
                    // To simplify have this separated here.
                    query += FSO_ITEMS_TABLE_AND_NAME_FILTER;    
                    match db.prepare(query.clone()).bind(&[JsValue::from(key1), JsValue::from(key2), JsValue::from(key3)]){
                        Ok(prepped_query) => {                
                            match prepped_query.all().await {
                                Ok(results) =>  {
                                    match results.results::<FsoItems>(){
                                        Ok(items) => {
                                            let mut query_return = FsoTablesQueryResults::new_results().await;
                                            query_return.fso_items = items;
                                            return Ok(query_return);
                                        },
                                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),                                            
                                    }
                                },
                                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                            }
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                

                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in FSO_ITEMS generic query.", mode).to_string().into()),
            }
        },
        Table::FsoTables => {
            query += FSO_TABLES_QUERY; 

            match mode {
                0 => (),
                1 => { query += FSO_TABLES_FILTER;
                    integer_key = true;
                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in FSO_Tables generic query.", mode).to_string().into()),
            }

        },
        Table::ParseBehaviors => {
            query += PARSE_BEHAVIORS_QUERY; 

            match mode {
                0 => (),
                1 => { query += PARSE_BEHAVIORS_FILTER;
                    integer_key = true;
                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Parse Behaviors generic query.", mode).to_string().into()),
            }

        },
        Table::Restrictions => {
            query += RESTRICTIONS_QUERY; 

            match mode {
                0 => (),
                1 => { query += RESTRICTIONS_FILTER;
                    integer_key = true;
                },
                    _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Restrictions generic query.", mode).to_string().into()),
            }

        },
/*         Table::Sessions => {
            query += SESSIONS_QUERY; 

            match mode {
                0 => (),
                1 => query = query + SESSIONS_FILTER_A + key2,// + SESSIONS_FILTER_B,
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Sessions generic query.", mode).to_string().into()),
            }

        },*/
        Table::TableAliases => {
            query += TABLE_ALIASES_QUERY; 

            match mode {
                0 => (),
                1 => { query += TABLE_ALIASES_FILTER;
                    integer_key = true;
                },
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Table Aliases generic query.", mode).to_string().into()),
            }

        },
        Table::Users => {
            query += USERS_QUERY; 

            match mode {
                0 => (),
                1 => { query += USERS_USER_ID_FILTER;
                    integer_key = true;
                },
                2 => query += USERS_USERNAME_FILTER,
                _ => return Err(format!("Internal Server Error: Out of range mode <{}> in Usernames generic query.", mode).to_string().into()),
            }

        },
    }

    let bound_query : D1PreparedStatement;

    if mode == 0 {
        bound_query = db.prepare(query.clone());
    } else {
        if integer_key == true{
            match from_str::<i32>(key1) {
                Ok(key_as_int) => {
                    match db.prepare(query.clone()).bind(&[key_as_int.into()]){
                        Ok(prepped_query)=> bound_query = prepped_query,
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                Err(e) => return Err(format!("Query:\" {} \" yielded an error since {} is not an integer. See: {}.", query, key1, e.to_string()).into()),
            }

        } else {
            match db.prepare(query.clone()).bind(&[key1.into()]){
                Ok(prepped_query)=> bound_query = prepped_query,
                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
            }
        }
    }

    let mut query_return = FsoTablesQueryResults::new_results().await;

    match table {
        Table::Actions => {
            match bound_query.all().await {
                Ok(results) =>{
                    match results.results::<ActionsInternal>() {
                        Ok(result) => {
                            query_return.actions = result;
                            return Ok(query_return);
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                Err(e)=> return Err(e),
            }
        },
        Table::EmailValidations => {
            //return Err("Got to generic email validation part 2.".to_string().into());
            match bound_query.all().await {
                Ok(results) =>{
                    match results.results::<EmailValidations>() {
                        Ok(result) => {
                            query_return.email_validations = result;
                            return Ok(query_return);
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                Err(e)=> return Err(e),
            }
        },
/*         Table::Sessions => {
            match bound_query.all().await {
                Ok(results) =>{
                    match results.results::<Session>() {
                        Ok(result) => {
                            query_return.sessions = result;
                            return Ok(query_return);
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                Err(e)=> return Err(e),
            }
        },*/
        Table::TableAliases => {
            match bound_query.all().await {
                Ok(results) =>{
                    match results.results::<TableAlias>() {
                        Ok(result) => {
                            query_return.table_aliases = result;
                            return Ok(query_return);
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                },
                Err(e)=> return Err(e),
            }
        },
    }                
}

pub async fn db_generic_update_query(table: &Table, mode: usize , key1: &String, key2: &String, ctx: &RouteContext<()>) -> Result<()> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => db_generic_update_query_db(table, mode, key1, key2, &db).await,
        Err(e) => return Err(e.into()),
    }
}

pub async fn db_generic_update_query_db(table: &Table, mode: usize , key1: &String, key2: &String, db: &D1Database) -> Result<()> {

    let mut query = "".to_string();

    match table {
        Table::Actions => {
            query = ACTIONS_PATCH_APPROVED_QUERY.to_owned() + BINDABLE_ACTIONS_FILTER_BY_ID; 
        },
        Table::BugReports => {

            match mode {
                0 => query += BUG_REPORT_PATCH_APPROVED_QUERY,
                1 => query += BUG_REPORT_PATCH_BUGTYPE_QUERY,
                2 => query += BUG_REPORT_PATCH_DESCRIPTION_QUERY,
                3 => query += BUG_REPORT_PATCH_STATUS_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Bug Report generic update query.".into()),
            }

            query += BUG_REPORT_FILTER_BINDABLE;
        }
        Table::Deprecations => {

            match mode {
                0 => query += DEPRECATIONS_PATCH_VERSION_QUERY,
                1 => query += DEPRECATIONS_PATCH_DESCRIPTION_QUERY,
                2 => query += DEPRECATIONS_PATCH_PARTIAL_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Deprecations generic update query.".into()),
            }

            query += DEPRECATIONS_FILTER_BINDABLE;
        },
        Table::EmailValidations => 
            return Err("Internal Server Error: Server attempting to update Email Validations with generic update query. Update aborted.".into()), 
        // This is definitely not done.  Figuring out all the relevant stuff for FSO items is a lot of effort.
        Table::FsoItems => {
            
            // we will need something like this to properly update item index
            //match db.prepare("SELECT table_index FROM fso_items WHERE item_id = ?1;").bind()

            query += &(FSO_ITEM_PATCH_STRINGS[mode].to_owned() + BINDABLE_FSO_ITEMS_FILTER_);

            match mode {
                // Sorry the order was arbitrary
                // 0 Default Value,   4 Major Version, 
                0 | 4 => { 
                    // no validation needed, even empty strings are ok 
                    match db.prepare(query.clone()).bind(&[JsValue::from(key1), JsValue::from(key2)]){
                        Ok(prepped_query)=> {
                            match prepped_query.run().await {
                                Ok(_) => return Ok(()),
                                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                            }
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }
                }, 
                
                // 5 Parent ID, 6 Table ID, 7 Table Index
                5 | 6 | 7 => {
                    if !is_integer(&key1){
                        return Err(format!("Cannot set an ID to {} since it is a non-integer.", key1).into());
                    };

                    match db.prepare(query.clone()).bind(&[JsValue::from(from_str::<i32>(&key1).unwrap()), JsValue::from(key2)]){
                        Ok(prepped_query)=> {
                            match prepped_query.run().await {
                                Ok(_) => return Ok(()),
                                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                            }
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }


                },

                // 1 Documentation, 2 Info_type, 3 Item Text
                1 | 2 | 3 => {
                    if key1.is_empty(){
                        return Err("Neither documentation, item text, nor info_type can be empty.".into());
                    }

                    match db.prepare(query.clone()).bind(&[JsValue::from(key1), JsValue::from(key2)]){
                        Ok(prepped_query)=> {
                            match prepped_query.run().await {
                                Ok(_) => return Ok(()),
                                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                            }
                        },
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }

                },
                
//                        4 => (), // TODO! please change to validate that the Info type is within the correct set in the future 
//                        5 => (), // please change to verify that major version is in the included set.

                _ => return Err("Internal Server Error: Out of range mode in FSO_ITEMS generic update query.".into()),
            }


        },
        Table::FsoTables => {
            return Err("Internal Server Error: Tables cannot be updated via the API.  This error message *should* be unreachable.  Please report!".into())
            
        },
        Table::ParseBehaviors => {
            match mode {
                0 => query += PARSE_BEHAVIORS_PATCH_BEHAVIOR_QUERY,
                1 => query += PARSE_BEHAVIORS_PATCH_DESCRIPTION_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Parse Behaviors generic update query.".into()),
            }

            query += PARSE_BEHAVIORS_FILTER_BINDABLE;
        },
        Table::Restrictions => {
            match mode {
                0 => query += RESTRICTIONS_PATCH_ILLEGAL_VALUE_FLOAT_QUERY,
                1 => query += RESTRICTIONS_PATCH_ILLEGAL_VALUE_INT_QUERY,
                2 => query += RESTRICTIONS_PATCH_MAX_STRING_LENGTH_QUERY,
                3 => query += RESTRICTIONS_PATCH_MAX_VALUE_QUERY,
                4 => query += RESTRICTIONS_PATCH_MIN_VALUE_QUERY,
                5 => query += RESTRICTIONS_PATCH_ALLOWED_VALUES_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Restrictions generic update query.".into()),
            }

            query += RESTRICTIONS_FILTER_BINDABLE;

        },/* 
        Table::Sessions => {
            match mode {
                0 => query += SESSIONS_PATCH_EXPIRATION_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Sessions generic update query.".into()),
            }

            query += SESSIONS_FILTER_USER_BINDABLE;
        },*/
        Table::TableAliases => {
            match mode {
                0 => query += TABLE_ALIASES_PATCH_FILENAME_QUERY,
                1 => query += TABLE_ALIASES_PATCH_TABLE_ID_QUERY,
                _ => return Err("Internal Server Error: Out of range mode in Table Aliases generic update query.".into()),
            }

            query += TABLE_ALIASES_FILTER_BINDABLE;
        },
        Table::Users => {
            return Err("Internal Server Error: Users cannot be updated via the generic update function.  This error message *should* be unreachable.  Please report!".into())
        },
    }

    match db.prepare(query.clone()).bind(&[JsValue::from(key1), JsValue::from(key2)]){
        Ok(prepped_query)=> {
            match prepped_query.run().await {
                Ok(_) => return Ok(()),
                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
            }
        },
        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
    }
}

// Email validations and sessions requires username as id to delete
pub async fn db_generic_delete(table: Table, id: &String, ctx: &RouteContext<()>) -> Result<()> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            let query: String;

            match table {
                Table::Actions => {
                    query = ACTIONS_DELETE_QUERY.to_owned() + BINDABLE_ACTIONS_FILTER_ID;                    
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
                },/*
                Table::Sessions => {
                    query = SESSIONS_DELETE_QUERY.to_owned() + SESSIONS_USER_ONLY_FILTER;                    
                },*/
                Table::TableAliases => {
                    query = TABLE_ALIASES_DELETE_QUERY.to_owned() + TABLE_ALIASES_FILTER;                    
                },
                Table::Users => {
                    return Err("Deletion of users not available at the api level.".to_string().into());
                },
            }

            match db.prepare(query.clone()).bind(&[id.into()]){
                Ok(prepped_query)=> {
                    match prepped_query.run().await {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
                    }        
                },
                Err(e) => return Err((db_prepare_query_error(e, query).await).into()),
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
        Err(e) => return Err((db_prepare_query_error(e, format!("SELECT active FROM users WHERE username = {}", email)).await).into()),
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
        Err(e) => return Err((db_prepare_query_error(e, format!("SELECT count(*) AS the_count FROM users WHERE username = {}", email)).await).into()),
    }    
}

#[derive(Serialize, Deserialize)]
struct EmailConfirmedBannedCheck{
    email_confirmed: i64,
    banned: i64,
}

pub async fn db_user_able_to_register(email: &String, db: &D1Database) -> worker::Result<bool> {
    let query = db.prepare("SELECT email_confirmed, banned FROM users WHERE username = ?" ).bind(&[email.into()]).unwrap();

    match query.first::<EmailConfirmedBannedCheck>(None).await {
        Ok(info_option) => {
            match info_option {
                Some(info) => return Ok(info.banned == 0 && info.email_confirmed == 0),
                None => return Ok(true),
            }
        },
        Err(e) => return Err((db_prepare_query_error(e, format!("SELECT email_confirmed, banned FROM users WHERE username = {}", email)).await).into()),
    }
}

#[derive(Serialize, Deserialize)]
struct EmailConfirmedCheck{
    email_confirmed: i64,
}

pub async fn db_user_is_incompletely_registered(email: &String, db: &D1Database) -> worker::Result<bool> {
    let query = db.prepare("SELECT email_confirmed FROM users WHERE username = ?" ).bind(&[email.into()]).unwrap();

    match query.first::<EmailConfirmedCheck>(None).await {
        Ok(info_option) => {
            match info_option {
                Some(info) => return Ok(info.email_confirmed == 0),
                None => return Ok(false),
            }
        },
        Err(e) => return Err((db_prepare_query_error(e, format!("SELECT email_confirmed FROM users WHERE username = {}", email)).await).into()),
    }
}

pub async fn db_is_user_banned_or_nonexistant(email: &String, db: &D1Database) -> worker::Result<bool> {
    let query = db.prepare("SELECT count(*) AS the_count FROM users WHERE username = ? AND banned = 0 AND email_confirmed = 1").bind(&[email.into()]).unwrap();

    match query.first::<BasicCount>(None).await {
        Ok(r) => {
            match r {
                Some(thing) => return Ok(thing.the_count > 0),
                None => return Ok(false),
            }
        },
        Err(e) => return Err((db_prepare_query_error(e, format!("SELECT count(*) AS the_count FROM users WHERE username = {} AND banned = 0 AND email_confirmed = 1", email)).await).into()),
    }        
}

pub async fn db_set_email_confirmed(email: &String, ctx: &RouteContext<()>) -> Result<()> {
    match ctx.env.d1(DB_NAME){
        Ok(db) => {
            match db.prepare("UPDATE users SET email_confirmed = 1, active = 1 WHERE username = ?").bind(&[email.into()]) {
                Ok(query) => {
                    match query.run().await {
                        Ok(_) => Ok(()),
                        Err(e) => return Err((db_prepare_query_error(e, format!("UPDATE users SET email_confirmed = 1, active = 1 WHERE username = {}", email)).await).into()),
                    }        
                },
                Err(e) => return Err((db_prepare_query_error(e, format!("UPDATE users SET email_confirmed = 1, active = 1 WHERE username = {}", email)).await).into()),
            }
        },
        Err(e) => return Err((db_prepare_query_error(e, format!("UPDATE users SET email_confirmed = 1, active = 1 WHERE username = {}", email)).await).into()),
    }
}

#[derive(Serialize, Deserialize)]
struct Role{
    role: i64,
}

#[derive(Deserialize, Serialize)]
struct BasicCount {
    the_count: i64,
}

#[derive(Deserialize,Serialize)]
struct Active {
    active: i64,
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
    let role_num : i64;
    
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

#[derive(Serialize, Deserialize)]
struct Salt {
    salt: String,
}

pub async fn db_get_user_salt(email: &String, ctx: &RouteContext<()> ) -> Result<String> {
    let db = ctx.env.d1(DB_NAME);

    match &db{
        Ok(connection) => {
            match connection.prepare("SELECT password2 AS salt FROM users WHERE username = ?").bind(&[JsValue::from(email)]){
                Ok(query) => {
                    match query.first::<Salt>(None).await {
                        Ok(r) => {
                            match r {
                                Some(r2) => Ok(r2.salt),
                                None => return Err("No Salt found for user".into()),
                            }
                        },
                        Err(e) => return Err((e.to_string() + " Database error").into()),
                    }
                },
                Err(e) => return Err((e.to_string() + "Database error").into()),
            }            
        },
        Err(e) => return Err((e.to_string() + " Database error").into()),
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

pub async fn db_insert_action(new_action: &ActionsInternal, db : &D1Database) -> Result<()> {
    match db.prepare(ACTIONS_INSERT_QUERY.to_string() + &new_action.timestamp.to_string() + ACTIONS_INSERT_QUERY_2 ).bind(&[
        JsValue::from(new_action.user_id),    
        JsValue::from(&new_action.action),    
        JsValue::from(new_action.approved_by_user),    
        JsValue::from(&new_action.route),    
        JsValue::from(new_action.user_id),    
        JsValue::from(new_action.approved),    
    ])
    {
        Ok(query) => {
            match query.all().await {
                Ok(_) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    };
}

pub async fn db_insert_deprecation(new_deprecation: &DeprecationNew, db : &D1Database) -> Result<i32> {

    match db.prepare(DEPRECATIONS_INSERT_QUERY.to_owned()).bind(&[JsValue::from(&new_deprecation.version),JsValue::from(&new_deprecation.description),JsValue::from(new_deprecation.partial),JsValue::from(new_deprecation.item_id)]){
        Ok(query) => {
            match query.all().await {
                Ok(_) => {
                    match db.prepare(format!("SELECT deprecation_id from deprecations where version = ?1 and description = ?2 and partial = {} ORDER BY deprecation_id desc LIMIT 1;)", new_deprecation.partial)).bind(&[JsValue::from(&new_deprecation.version),JsValue::from(&new_deprecation.description)]) {
                        Ok(query2) => {
                            match query2.first::<i32>(Some("deprecation_id")).await{
                                Ok(thing) => {
                                    match thing {
                                        Some(value) => return Ok(value),
                                        None => return Err("Could not get id after inserting deprecation.".into()),
                                    }
                                },
                                Err(e) => return Err(e.into()),
                            }
                        },
                        Err(e) => return Err(e.into()),
                    }

                },
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }
}

pub async fn db_insert_restriction(new_restriction: &RestrictionNew, db : &D1Database) -> Result<i32> {
    let mut new_id = -1; // define here to allow 

    // Add row with default parameters, retrieve ID. The database is supposed to do this query all at once, so it should avoid concurrency issues.
    match db.prepare(format!("INSERT INTO restrictions (min_value, max_value, max_string_length, illegal_value_int, illegal_value_float, allowed_values) VALUES ( ?, {}, {} , {}, {}, \"\"; SELECT restriction_id from restrictions ORDER BY restriction_id desc LIMIT 1;)", DUMMY_FLOAT, DUMMY_INT, DUMMY_INT, DUMMY_FLOAT)).bind(&[JsValue::from(DUMMY_FLOAT)]) {
        Ok(query) => {
            match query.first::<i32>(Some("restriction_id")).await {
                Ok(result) => {
                    match result{
                        Some(id) => new_id = id,
                        None => return Err("Did not find new restriction id after creating new row.".into()),
                    }
                },
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }


    // 0 min_value, 1 Max_value, 2 max string length, 3 illegal value int, 4 illegal value float, 5 min and max int, 6 min and max float, 7 value list

    /*          0 => query += RESTRICTIONS_PATCH_ILLEGAL_VALUE_FLOAT_QUERY,
                1 => query += RESTRICTIONS_PATCH_ILLEGAL_VALUE_INT_QUERY,
                2 => query += RESTRICTIONS_PATCH_MAX_STRING_LENGTH_QUERY,
                3 => query += RESTRICTIONS_PATCH_MAX_VALUE_QUERY,
                4 => query += RESTRICTIONS_PATCH_MIN_VALUE_QUERY,
                5 => query += RESTRICTIONS_PATCH_ALLOWED_VALUES_QUERY, */
    match new_restriction.type_of{
        0 => {
            match db_generic_update_query_db(&Table::Restrictions,4,&new_id.to_string(),&new_restriction.float_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),  
            } 
        },
        1 => {
            match db_generic_update_query_db(&Table::Restrictions,3,&new_id.to_string(),&new_restriction.float_value1.to_string(), db).await{
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        },
        2 => {
            match db_generic_update_query_db(&Table::Restrictions,2,&new_id.to_string(),&new_restriction.int_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        }
        3 => {
            match db_generic_update_query_db(&Table::Restrictions,1,&new_id.to_string(),&new_restriction.int_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        },
        4 => { 
            match db_generic_update_query_db(&Table::Restrictions,0,&new_id.to_string(),&new_restriction.float_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        },
        5 => {
            match db_generic_update_query_db(&Table::Restrictions,4,&new_id.to_string(),&new_restriction.int_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }

            match db_generic_update_query_db(&Table::Restrictions,3,&new_id.to_string(),&new_restriction.int_value2.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        
        },
        6 => {
            match db_generic_update_query_db(&Table::Restrictions,4,&new_id.to_string(),&new_restriction.float_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }

            match db_generic_update_query_db(&Table::Restrictions,3,&new_id.to_string(),&new_restriction.float_value1.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()),
            }
        
        },
        7 => {
            match db_generic_update_query_db(&Table::Restrictions,5,&new_id.to_string(),&new_restriction.allowed_value_list.to_string(), db).await {
                Ok(_)=>(),
                Err(e)=> return Err(e.into()), 
            }
        },
        _ => return Err("New restriction type out of range.".into()),
    }

    Ok(new_id)
}

pub async fn db_insert_item(new_item : &NewItem, db : &D1Database) -> Result<i32>{
    match db.prepare("UPDATE fso_items SET table_index = table_index + 1 WHERE table_id = ?1 AND table_index >= ?2").bind(&[JsValue::from(new_item.table_id), JsValue::from(new_item.table_index)]){
        Ok(_) => (),
        Err(e) => return Err(e.into()), 
    }

    match db.prepare(FSO_ITEMS_INSERT_QUERY).bind(&[
        JsValue::from(&new_item.item_text), 
        JsValue::from(&new_item.documentation), 
        JsValue::from(&new_item.major_version),
        JsValue::from(new_item.parent_id),
        JsValue::from(new_item.table_id),
        JsValue::from(new_item.deprecation_id),
        JsValue::from(new_item.restriction_id),
        JsValue::from(&new_item.info_type),
        JsValue::from(new_item.table_index),
        JsValue::from(&new_item.default_value)]) 
    {
        Ok(query) => {
            match query.all().await {
                Ok(_) => (),
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }
    // uses FSO_ITEMS_TABLE_AND_NAME_FILTER
    match db_generic_search_query_db(&Table::FsoItems, 2, &new_item.table_id.to_string(),&new_item.item_text, &new_item.parent_id.to_string(), &db).await {
        Ok(results) => 
        {
            if results.fso_items.is_empty(){
                return Err("Unable to retrieve id after insertion into items table! Must be a logic error, please report!".to_string().into());
            }
            return Ok(results.fso_items[0].item_id)
        },
        Err(e) => return Err(e.into()),
    }
}

pub async fn db_session_add(token: &String, email: &String, time: &String, ctx: &RouteContext<()>) -> worker::Result<()> {

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

pub async fn db_insert_bug_report(username: &String, bug_type: &String, descripton: &String,  ctx: &RouteContext<()>) -> worker::Result<()> {
    /*user_id: i64,
    bug_type: String,
    description: String,
    status: i64,
    timestamp: String,*/

    let mut user_id = -1;

    if username != "Anonymous User"{
        match db_generic_search_query_ctx(&Table::Users, 2, username, &"".to_string(), &"".to_string(), ctx).await {
            Ok(results) => {
                if !results.users.is_empty() {
                    user_id = results.users.first().unwrap().id;
                }
            },
            Err(_) => (),
        }
    }

    match  ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let query = format!("INSERT INTO bug_reports (user_id, bug_type, description, status, timestamp) VALUES (\"{}\", ?1, ?2, \"{}\", \"{}\")", user_id, 0, Utc::now().format(DB_TIME_FORMAT).to_string());

            match db.prepare(query).bind(&[JsValue::from(bug_type), JsValue::from(descripton)]) {
                Ok(statement) => {
                    match statement.run().await {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err(e),
                    }
                },
                Err(e)=> return Err(e),
            }

        },
        Err(e) => return Err(e),
    }


}

pub async fn db_insert_error_record(error: &String,  ctx: &RouteContext<()>) -> Result<()> {
    match  ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let query = ERROR_REPORT_INSERT_QUERY.to_owned() + &get_current_time_i64().to_string() + ERROR_REPORT_INSERT_QUERY_2;

            match db.prepare(query).bind(&[JsValue::from(error)]) {
                Ok(statement) => {
                    match statement.run().await {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err(e),
                    }
                },
                Err(e)=> return Err(e),
            }
        },
        Err(e) => return Err(e),
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
                            
                            return Ok(time.parse::<i64>().unwrap() < results[0].expiration);
                        },
                        Err(_) => return Ok(false),        
                    },
                Err(e)=> Err(e),
            }
        },
        Err(e)=> return Err(e),
    }
}

#[derive(Serialize, Deserialize)]
struct ResetCodeRecord {
    code: String,
    email: String,
    attempt_count: i64,
    expiration: String,
}

pub async fn db_add_code_reset(username: &String, code: &String, ctx: &RouteContext<()>) -> Result<()> {
    match  ctx.env.d1(DB_NAME) {
        Ok(db) => {

            let prep_query = "DELETE FROM email_resets WHERE email = ?";
            match db.prepare(prep_query).bind(&[username.into()]){
                Ok(prepared) => {
                    match prepared.run().await {
                    _ => (),
                    }
                },
                Err(_) => (),
            }

            let query = "INSERT INTO email_resets (code, email, attempt_count, expiration) VALUES (?1, ?2, 0, ?3);";
            let mut time =  Utc::now();
            time = time + TimeDelta::minutes(30);

            match db.prepare(query).bind(&[JsValue::from(code), JsValue::from(username), JsValue::from(time.format(DB_TIME_FORMAT).to_string())]) {
                Ok(statement) => {
                    let _ = statement.run().await;                    
                    return Ok(())},
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }
}

// TODO, shortsightedly, this only lets you try to set the code once.  We need to separate out the deletion into the calling code to do it properly.
// OR maybe check password requirements before checking the code.
pub async fn db_check_code(username: &String, code: &String, ctx: &RouteContext<()>) -> Result<()> {
    match  ctx.env.d1(DB_NAME) {
        Ok(db) => {
            let query = "SELECT code, email, attempt_count, expiration FROM email_resets WHERE email = ?;";
    
            match db.prepare(query).bind(&[username.into()]) {
                Ok(statement) => {                    
                    match statement.all().await {
                        Ok(results) =>{
                            match results.results::<ResetCodeRecord>() {
                                Ok(result) => {
                                    if result.is_empty() {
                                        return Err("{\"Error\":\"Password Reset Failed\"}".to_string().into())
                                    }

                                    let the_result = &result[0];
                                    let current_time = Utc::now();

                                    match DateTime::parse_from_str(&the_result.expiration, DB_TIME_FORMAT) {
                                        Ok(session_time) => if session_time < current_time {
                                            let query2a = "DELETE FROM email_resets WHERE email = ?";
                                            match db.prepare(query2a).bind(&[username.into()]){
                                                Ok(prepared) => {
                                                    match prepared.run().await {
                                                    _ => (),
                                                    }
                                                },
                                                Err(_) => (),
                                            }
                                            return Err("{\"Error\":\"Password Reset Failed\"}".to_string().into())                                            
                                        },
                                        Err(_) => return Err("{\"Error\":\"Internal error caused password reset fail. Please ask an admin to check the expiration date format in the database. | IEC00147\"}".to_string().into()),
                                    }

                                    if the_result.attempt_count + 1 > 4 {
                                        let query2b = "DELETE FROM email_resets WHERE email = ?";
                                        match db.prepare(query2b).bind(&[username.into()]){
                                            Ok(prepared) => {
                                                match prepared.run().await {
                                                _ => (),
                                                }
                                            },
                                            Err(_) => (),
                                        }
                                        
                                        return Err("{\"Error\":\"Password Reset Failed\"}".to_string().into())
                                        
                                    }

                                    if &the_result.code != code {
                                        let query3 = "UPDATE email_resets SET attempt_count = attempt_count + 1 WHERE email = ?";
                                        match db.prepare(query3).bind(&[username.into()]){
                                            Ok(bound_query) => {
                                                match bound_query.run().await {
                                                    _ => return Err("{\"Error\":\"Password Reset Failed\"}".to_string().into()),
                                                }    
                                            },
                                            Err(_) => return Err("{\"Error\":\"Password Reset Failed\"}".to_string().into()),
                                        }
                                    }

                                    let query2c = "DELETE FROM email_resets WHERE email = ?";
                                    match db.prepare(query2c).bind(&[username.into()]){
                                        Ok(prepared) => {
                                            match prepared.run().await {
                                            _ => (),
                                            }
                                        },
                                        Err(_) => (),
                                    }
                                },
                                Err(_) => return Err("{\"Error\":\"Password reset failed because of internal error | IEC00148\"}".to_string().into()),
                            }
                        },
                        Err(_) => return Err("{\"Error\":\"Password reset failed because of internal error | IEC00149\"}".to_string().into()),
                    }

                },
                
                Err(_) => return Err("{\"Error\":\"Password reset failed because of internal error | IEC00150\"}".to_string().into()),
            }
        },
        Err(_) => return Err("{\"Error\":\"Password reset failed because of internal error | IEC00151\"}".to_string().into()),
    }

    return Ok(())
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