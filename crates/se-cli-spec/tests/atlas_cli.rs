//! CLI grammar tests for Atlas subcommands.
use se_core::ops::AnyOp;

#[test]
fn bare_atlas_is_help_and_keeps_all_five_typed_queries() -> Result<(), Box<dyn std::error::Error>> {
    let matches = se_cli_spec::cli_command().try_get_matches_from(["se", "atlas"])?;
    let AnyOp::MetaHelp(help) = se_cli_spec::from_matches(&matches)? else {
        panic!("bare atlas is not help")
    };
    assert_eq!(help.path, ["atlas"]);
    for command in ["find", "refs", "impact", "changes", "outline"] {
        let mut args = vec!["se", "atlas", command];
        if command != "changes" {
            args.push("good.js");
        } else {
            args.extend(["--since", "unused-help-cursor"]);
        }
        args.push("--help");
        let matches = se_cli_spec::cli_command().try_get_matches_from(args)?;
        assert_eq!(se_cli_spec::selected_meta(&matches)?.name, "meta.help");
    }
    Ok(())
}
