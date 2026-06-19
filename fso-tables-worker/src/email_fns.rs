use serde::{Deserialize, Serialize};

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
