use std::error::Error;

use async_trait::async_trait;
use jmap_client::client::Client as JmapClient;
use jmap_client::mailbox::Property as MailboxProperty;
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
        if self
            .mailbox_get("Verification", Some(vec![MailboxProperty::Id]))
            .await?
            .is_none()
        {
            self.mailbox_create(
                "Verification",
                None::<String>,
                jmap_client::mailbox::Role::None,
            )
            .await?
            .take_id();
        }

        Ok(())
    }

    async fn send_verification_email(
        &self,
        code: String,
        recipient_addr: String,
    ) -> Result<(), Box<dyn Error>> {
        let mut context = tera::Context::new();
        context.insert("code", &code);
        let html_body = TEMPLATES.render("verification", &context)?;
        // create the email object

        // create the email submission
        // return submission id for polling?
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
