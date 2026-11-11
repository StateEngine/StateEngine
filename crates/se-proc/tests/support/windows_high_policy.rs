use super::*;
use crate::windows_policy_fixture::*;
// High labels require an actual elevated native run. This test is explicit,
// never silently skipped by an ordinary Medium-token pass.
#[test]
#[ignore = "run --ignored --exact uninstall::staging::judges::high_label_policy under a High token"]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn high_label_policy() -> Check {
    assert!(
        elevated()?,
        "this judge requires an elevated High-token runner"
    );
    let home = Home::new()?;
    let user = user()?;
    for (index, (directory, flags, mask, label, accepted)) in [
        (true, "OICI", "NW", "HI", true),
        (false, "", "NW", "HI", true),
        (true, "OICI", "NW", "ME", false),
        (true, "OICI", "NW", "LW", false),
        (true, "OICI", "NR", "HI", false),
        (true, "OICIIO", "NW", "HI", false),
        (true, "OI", "NW", "HI", false),
        (true, "CI", "NW", "HI", false),
    ]
    .into_iter()
    .enumerate()
    {
        let path = home.0.join(format!("label-{index}"));
        let descriptor = Descriptor::new(&format!(
            "O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)S:(ML;{flags};{mask};;;{label})"
        ))?;
        let attributes = descriptor.attributes();
        if directory {
            assert_ne!(
                // SAFETY: unique owned path and retained descriptor apply the label at creation.
                unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attributes) },
                0,
                "create label fixture: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: exact owned path with no-follow directory/file flags and retained SD.
        let file = File::from(own(unsafe {
            CreateFileW(
                wide(path.as_os_str()).as_ptr(),
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                if directory { ptr::null() } else { &attributes },
                if directory { OPEN_EXISTING } else { CREATE_NEW },
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
                ptr::null_mut(),
            )
        })?);
        // Query the native label independently before interpreting any refusal.
        let mut raw = ptr::null_mut();
        let mut sacl = ptr::null_mut();
        // SAFETY: retained file handle and writable descriptor/SACL outputs.
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl,
                &mut raw,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32).into());
        }
        let _readback = Descriptor(raw);
        assert!(!sacl.is_null(), "created label absent");
        assert_eq!(
            // SAFETY: GetSecurityInfo returned this retained valid native ACL.
            unsafe { (*sacl).AceCount },
            1,
            "fixture did not retain exactly one mandatory ACE"
        );
        // SAFETY: queried ACL stays alive in _readback and GetAce bounds its output.
        let mut ace = ptr::null_mut();
        // SAFETY: retained queried SACL and writable ACE output.
        assert_ne!(unsafe { GetAce(sacl, 0, &mut ace) }, 0);
        // SAFETY: the independently queried mandatory ACE has this native layout.
        let actual = unsafe { &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
        assert_eq!(
            actual.Header.AceType, 0x11,
            "fixture label normalized into another ACE type"
        );
        let expected = descriptor.acl(true)?;
        let mut expected_ace = ptr::null_mut();
        // SAFETY: retained fixture SDDL ACL and writable ACE output.
        assert_ne!(unsafe { GetAce(expected, 0, &mut expected_ace) }, 0);
        // SAFETY: SDDL ML ACE supplies this exact native layout.
        let expected = unsafe { &*expected_ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
        assert_eq!(
            actual.Header.AceFlags, expected.Header.AceFlags,
            "fixture flags changed"
        );
        assert_eq!(actual.Mask, expected.Mask, "fixture mask changed");
        assert_ne!(
            // SAFETY: both retained mandatory ACEs contain valid SIDs.
            unsafe {
                EqualSid(
                    (&raw const actual.SidStart).cast_mut().cast(),
                    (&raw const expected.SidStart).cast_mut().cast(),
                )
            },
            0,
            "fixture label SID changed"
        );
        match verify_high(&file, directory) {
            Ok(()) => assert!(
                accepted,
                "accepted label-{index}: directory={directory} {flags}/{mask}/{label}"
            ),
            Err(error) => {
                assert!(!accepted, "valid High label refused: {error:?}");
                assert_eq!(error.operation, "verify mandatory uninstall label");
            }
        }
    }
    println!("High label: 2 valid and 6 refused native fixtures passed");
    Ok(())
}
