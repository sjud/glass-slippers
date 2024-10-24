/*
    For the email client, we want to provide a way to automate the sending of emails to our stalwart instance.
    Ultimately it'd be nice to have a UI and fancy ai automated marketing blah blah blah
    but we should focus on completing our current flows for authentication,
    verification, recovery

*/

use std::error::Error;

use async_trait::async_trait;
use jmap_client::client::Client as JmapClient;
use tera::Tera;
lazy_static::lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let tera = match Tera::new("email_templates/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera
    };
}
pub async fn build_email_client() -> JmapClient {
    JmapClient::new()
        // we'll probably need these.
        .credentials(("admin", "IXkpxNOrbH"))
        .connect("http://localhost:8080")
        .await
        .expect("JmapClient connection or die")
}
#[async_trait]
pub trait EmailClient {
    async fn create_verification_mailbox(&self) -> Result<(), Box<dyn Error>>;
    async fn send_verification_email(
        &self,
        code: String,
        recipient_addr: String,
    ) -> Result<(), Box<dyn Error>>;
    async fn send_recovery_email(&self);
}
#[async_trait]
impl EmailClient for JmapClient {
    async fn create_verification_mailbox(&self) -> Result<(), Box<dyn Error>> {
        self.mailbox_create(
            "Verification",
            None::<String>,
            jmap_client::mailbox::Role::None,
        )
        .await
        .unwrap()
        .take_id();
        Ok(())
    }

    async fn send_verification_email(
        &self,
        code: String,
        recipient_addr: String,
    ) -> Result<(), Box<dyn Error>> {
        let mut context = tera::Context::new();
        context.insert("code", &code);
        let template = TEMPLATES.render("verification", &context)?;
        let mut request = &self.build();
        Ok(())
    }
    async fn send_recovery_email(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_connect() {
        build_email_client().await;
    }
}
