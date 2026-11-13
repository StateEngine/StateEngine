use se_store_contract::channel::Opaque;
impl<const MAX: usize> crate::sql_value::Param for Opaque<MAX> {
    fn sql_value(&self) -> crate::StoreResult<rusqlite::types::Value> {
        Ok(rusqlite::types::Value::Text(self.as_str().to_owned()))
    }
}
