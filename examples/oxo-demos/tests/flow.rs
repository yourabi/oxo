//! The same flow the `hello` binary runs, asserted — so the demo can't drift.

#[tokio::test(flavor = "multi_thread")]
async fn hello_demo_serves_the_trivial_app() {
    let body = oxo_demos::run_hello_demo().await.expect("hello demo");
    assert!(body.contains("Hello from Oxo!"), "body: {body}");
    assert!(body.contains("PATH_INFO=/hello"), "body: {body}");
    assert!(body.contains("QUERY_STRING=demo=1"), "body: {body}");
}
