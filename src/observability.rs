#[cfg(test)]
pub mod tests {
    #[tokio::test]
    pub async fn test_basic_tracing_structure() {
        let traces = r#"
            2024-10-01T20:09:34.523779Z ERROR dev_example::app: Hello while doing SSR.
            2024-10-01T20:09:35.356575Z TRACE __click_me{count=0}: dev_example::app: Hello from click_me
            2024-10-01T20:09:35.356621Z DEBUG __click_me{count=0}:click_me inner span: dev_example::app: Hello from click_me inner span...
            2024-10-01T20:09:35.356641Z  INFO __click_me{count=0}: dev_example::app: Hello after click me inner span.
            2024-10-01T20:09:35.356660Z  INFO __click_me{count=0}:login{user="ferris" user.email="ferris@rust-lang.org"}: dev_example::app: is_special=true
            2024-10-01T20:09:35.356675Z  INFO __click_me{count=0}: dev_example::app: Hello after click me inner span.
            2024-10-01T20:09:35.356690Z  INFO __click_me{count=0}:login{user="dogbones"}: dev_example::app: is_special=true
        "#;
    }
}
