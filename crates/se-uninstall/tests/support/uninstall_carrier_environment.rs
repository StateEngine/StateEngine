use super::*;

#[test]
fn carrier_environment_has_only_four_native_entries()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir();
    let block = environment(&root)?;
    assert!(block.ends_with(&[0, 0]));
    let entries = block
        .split(|unit| *unit == 0)
        .filter(|entry| !entry.is_empty())
        .map(String::from_utf16)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(entries.len(), 4);
    let values = entries
        .iter()
        .map(|entry| entry.split_once('=').ok_or("invalid environment entry"))
        .collect::<std::result::Result<std::collections::BTreeMap<_, _>, _>>()?;
    assert_eq!(
        values.keys().copied().collect::<Vec<_>>(),
        ["SystemRoot", "TEMP", "TMP", "windir"]
    );
    assert_eq!(
        values["TEMP"],
        root.to_str().ok_or("fixture path must be UTF-8")?
    );
    assert_eq!(values["TMP"], values["TEMP"]);
    assert_eq!(values["SystemRoot"], values["windir"]);
    assert!(Path::new(values["SystemRoot"]).is_absolute());
    Ok(())
}
