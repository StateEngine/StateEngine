//! Malformed resume positions have the same actionable domain error at both ingresses.
use se_core::ops::{cli_command, decode_tool, from_matches};
use se_types::{Code, RenderCx};

#[test]
fn malformed_resume_positions_keep_their_code_and_fresh_read_remedy()
-> Result<(), Box<dyn std::error::Error>> {
    for token in [String::new(), "bad cursor".into(), "x".repeat(4097)] {
        let matches = cli_command().try_get_matches_from(["se", "resume", "--since", &token])?;
        let cli = from_matches(&matches)
            .err()
            .ok_or("CLI accepted malformed cursor")?;
        let mcp = decode_tool("stateengine_resume", serde_json::json!({"since":token}))
            .err()
            .ok_or("MCP accepted malformed cursor")?;
        for error in [cli, mcp] {
            assert_eq!(error.code(), Code::CursorInvalid);
            assert!(
                error
                    .body
                    .remedy(&RenderCx::default())?
                    .text
                    .contains("without --since")
            );
        }
    }
    let typed = decode_tool("stateengine_resume", serde_json::json!({"since":42}))
        .err()
        .ok_or("non-string cursor accepted")?;
    assert_eq!(typed.code(), Code::CursorInvalid);
    Ok(())
}
