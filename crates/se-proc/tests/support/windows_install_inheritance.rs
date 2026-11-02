use super::*;
use crate::windows_policy_fixture::*;
#[test]
fn install_hold_spawn_keeps_claim_and_stdio_but_excludes_other_handles() -> Check {
    let home = Home::new()?;
    let excluded = event()?;
    let claim = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(home.0.join("owned-claim"))?;
    assert_eq!(
        flags(claim.as_raw_handle())? & HANDLE_FLAG_INHERIT,
        0,
        "claim original must not be inheritable"
    );
    let plan = ChildPlan {
        report: home.0.join("child.report"),
        excluded: excluded.as_raw_handle() as usize,
        allowed: None,
        input: None,
        claim: Some(file_key(claim.as_raw_handle())?),
    };
    let args = child_args(&plan)?;
    assert_eq!(
        run(&claim, std::env::current_exe()?.as_os_str(), &args, None)?,
        0,
        "native install child failed"
    );
    report(&plan, &excluded)
}
