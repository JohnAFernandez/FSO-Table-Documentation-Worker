use crate::{err_specific, err_specific_and_add_report, send_success, secrets::SMTP_API_KEY};

use serde::{Deserialize, Serialize};
use worker::*;
use email_address::{EmailAddress};
use wasm_bindgen::JsValue;

#[derive(Serialize, Deserialize)]
pub struct EmailSubmission{
    pub email: String,
}

#[derive(Serialize)]
pub struct FullEmailAddress {
    pub name: String,
    pub email: String,
}

impl FullEmailAddress {
    pub fn create_full_email(name: String, email:String) -> FullEmailAddress {
        FullEmailAddress{ name, email}
    }
}


#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct EmailMessage {
    pub sender: FullEmailAddress, 
    pub to: Vec<FullEmailAddress>,
    pub subject: String,
    pub htmlContent: String, // do not change, as this needs to have this case to be properly processed by Bevo
}

impl EmailMessage {
    pub fn create_activation_email(code: &String) -> EmailMessage{
        EmailMessage{
            sender : FullEmailAddress::create_full_email("FSO Tables Database User Activations".to_string(), "activations@fsotables.com".to_string()),
            to : vec![], 
            subject : "Account Confirmation Code".to_string(),
            htmlContent : format!("
            <div style=\"background-color: #000000; padding-top: 20px; padding-bottom: 20px; border-radius: 5px;\">
                <div style=\"text-align:center; font-family: calibri; padding: 50px; background-color: #242424; color: #cecece; margin-left:50px; margin-right:50px; border-radius: 5px;\">
                    <h2>
                        Welcome to Ganymede, the Freespace Open Table Option Database
                    </h2>
                    <h3>
                        To activate your account enter this confirmation code at the ganymede website
                    </h3>
                    <div style=\"display: grid;\">
                        <h1 style=\"background-color: #333333; border-radius: 5px; padding:10px; padding-left:15px; padding-right:15px; letter-spacing: 0.5em;\">
                            {}
                        </h1>
                    </div>
                    <br>
                    <h4>Account confirmation codes expire in 24 hours.
                        <br><br>
                        If you are unsure why you got this email, please permanently delete it.
                        <br><br>
                        Please do not reply, this email address is not monitored.
                    </h4>
                </div>
            </div>", code),
        }
    }

    pub fn create_password_reset_email(code: &String) -> EmailMessage{
        EmailMessage{
            sender : FullEmailAddress::create_full_email("FSO Tables Database Password Reset".to_string(), "credentials@fsotables.com".to_string()),
            to : vec![], 
            subject : "Account Reset Code".to_string(),
            htmlContent : format!("
            <div style=\"background-color: #000000; padding-top: 20px; padding-bottom: 20px; border-radius: 5px;\">
                <div style=\"text-align:center; font-family: calibri; padding: 50px; background-color: #242424; color: #cecece; margin-left:50px; margin-right:50px; border-radius: 5px;\">
                    <h2>
                        We received a password reset request for your Ganymede account.
                        <br>
                        Here is your confirmation code:
                    </h2>
                    <div style=\"display: grid;\">
                        <h1 style=\"background-color: #333333; border-radius: 5px; padding:10px; padding-left:15px; padding-right:15px; letter-spacing: 0.5em;\">
                            {}
                        </h1>
                    </div>
                    <br>
                    <h4>
                        Confirmation codes expire in 30 minutes.
                        <br><br>
                        If you are unsure why you got this code, please permanently delete this email.
                        <br><br>
                        Please do not reply, this email address is not monitored.
                    </h4>
                </div>
            </div>", code),
        }
    }
}

pub async fn send_password_reset_email(address : &String, code: &String, ctx: &RouteContext<()>) -> worker::Result<worker::Response> {
    if !(EmailAddress::is_valid(&address)){
        return err_specific(format!("{{\"Error\":\"Tried to send automated email to invalid email address {}\"}}", address)).await
    }

    let headers : Headers = Headers::new();
    match headers.append("content-type", "application/json"){
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00127\"}".to_string(),&(e.to_string() + " | IEC00127"), 500, &ctx).await,
    }

    match headers.append("accept", "application/json") {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00128\"}".to_string(),&(e.to_string() + " | IEC00128"), 500, &ctx).await,
    }

    match headers.append("api-key", SMTP_API_KEY) {
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
                Ok(_) => return send_success(&"{\"Response\":\"Email sent!\"}".to_string(), &"".to_string()).await,
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

    let headers : Headers = Headers::new();
    match headers.append("content-type", "application/json"){
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00125\"}".to_string(),&(e.to_string() + " | IEC00125"), 500, &ctx).await,
    }

    match headers.append("accept", "application/json") {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00126\"}".to_string(),&(e.to_string() + " | IEC00126"), 500, &ctx).await,
    }

    match headers.append("api-key", SMTP_API_KEY) {
        Ok(_) => (),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00061\"}".to_string(),&(e.to_string() + " | IEC00061"), 500, &ctx).await,
    }

    let mut message: EmailMessage = EmailMessage::create_activation_email(activation_key);
    message.to.push(FullEmailAddress::create_full_email("User".to_string(), address.to_string()));

    let jvalue_out : JsValue;

    match serde_json::to_string(&message) {
        Ok(json_message) => jvalue_out = JsValue::from_str(&json_message),
        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00062\"}".to_string(),&(e.to_string() + " | IEC00062"), 500, &ctx).await,
    }

    let mut outbound_request = RequestInit::new();
    outbound_request.with_method(Method::Post).with_headers(headers).with_body(Some(jvalue_out));
    
    let imminent_request = worker::Request::new_with_init("https://api.brevo.com/v3/smtp/email", &outbound_request).unwrap();
    
    match worker::Fetch::Request(imminent_request).send().await {
        Ok(mut res) => { 
            match res.text().await {
                Ok(_) => return send_success(&"{\"Response\":\"Email sent!\"}".to_string(), &"".to_string()).await,
                Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00063\"}".to_string(),&(e.to_string() + " | IEC00063"), 500, &ctx).await,
            }
        },

        Err(e) => return err_specific_and_add_report("{\"Error\":\"Internal Database Function Error, please check your inputs and try again. | IEC00064\"}".to_string(),&(e.to_string() + " | IEC00064"), 500, &ctx).await,
    }

}