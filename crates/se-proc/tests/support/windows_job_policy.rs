use super::*;
use crate::windows_policy_fixture::*;
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
#[test]
fn job_requires_exact_user_and_system_allow_aces() -> Check {
    crate::initialize_file_creation_owner()?;
    let user = user()?;
    let good = format!("D:P(A;;0x1f003f;;;{user})(A;;0x1f003f;;;SY)");
    let descriptor = Descriptor::new(&format!("O:{user}{good}"))?;
    // SAFETY: unnamed owned job and retained descriptor; no process is assigned.
    let raw = own(unsafe { CreateJobObjectW(&descriptor.attributes(), ptr::null()) })?;
    // Transfer the unique job handle to the production RAII wrapper.
    use std::os::windows::io::IntoRawHandle;
    let job = Handle::new(raw.into_raw_handle(), "own policy fixture job")
        .map_err(|e| format!("{e:?}"))?;
    verify_job(&job).map_err(|e| format!("positive job: {e:?}"))?;
    for (label, acl, reason) in [
        (
            "one ACE",
            format!("D:P(A;;GA;;;{user})"),
            "exact user/SYSTEM job ACL required",
        ),
        (
            "third ACE",
            format!("{good}(A;;GA;;;WD)"),
            "exact user/SYSTEM job ACL required",
        ),
        (
            "duplicate user",
            format!("D:P(A;;GA;;;{user})(A;;GA;;;{user})"),
            "unexpected or duplicate principal",
        ),
        (
            "duplicate SYSTEM",
            "D:P(A;;GA;;;SY)(A;;GA;;;SY)".into(),
            "unexpected or duplicate principal",
        ),
        (
            "foreign principal",
            format!("D:P(A;;GA;;;{user})(A;;GA;;;WD)"),
            "unexpected or duplicate principal",
        ),
        (
            "partial access",
            format!("D:P(A;;0x1;;;{user})(A;;GA;;;SY)"),
            "old job access mask changed",
        ),
        (
            "deny ACE",
            format!("D:P(D;;GA;;;{user})(A;;GA;;;SY)"),
            "unexpected old job ACE",
        ),
        (
            "ACE flags",
            format!("D:P(A;OI;GA;;;{user})(A;;GA;;;SY)"),
            "unexpected old job ACE",
        ),
    ] {
        set_dacl(job.0, SE_KERNEL_OBJECT, &acl)?;
        let error = verify_job(&job)
            .err()
            .ok_or(format!("{label} job accepted"))?;
        assert!(format!("{error:?}").contains(reason), "{label}: {error:?}");
        set_dacl(job.0, SE_KERNEL_OBJECT, &good)?;
        verify_job(&job).map_err(|e| format!("restored {label}: {e:?}"))?;
    }
    set_dacl(
        job.0,
        SE_KERNEL_OBJECT,
        &format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})"),
    )?;
    verify_job(&job).map_err(|e| format!("reversed GENERIC_ALL: {e:?}"))?;
    println!("job policy: 8 malformed ACLs refused; exact user/SYSTEM accepted in both orders");
    Ok(())
}
