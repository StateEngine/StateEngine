//! Checked signed SQLite boundaries for unsigned domain counters.
use crate::{StoreResult, error::*};
use rusqlite::{Row, types::Value};
pub(crate) trait Param {
    fn sql_value(&self) -> StoreResult<Value>;
}
macro_rules! signed {($($t:ty),*)=>{$(impl Param for $t {fn sql_value(&self)->StoreResult<Value>{Ok(Value::Integer(i64::from(*self)))}})*}}
macro_rules! unsigned {($($t:ty),*)=>{$(impl Param for $t {fn sql_value(&self)->StoreResult<Value>{Ok(Value::Integer(i64::try_from(*self).map_err(invalid)?))}})*}}
signed!(i64, i32, i16, i8, u16, u8, u32);
unsigned!(u64, usize);
impl Param for bool {
    fn sql_value(&self) -> StoreResult<Value> {
        Ok(Value::Integer(i64::from(*self)))
    }
}
impl Param for str {
    fn sql_value(&self) -> StoreResult<Value> {
        Ok(Value::Text(self.into()))
    }
}
impl Param for String {
    fn sql_value(&self) -> StoreResult<Value> {
        self.as_str().sql_value()
    }
}
impl Param for [u8] {
    fn sql_value(&self) -> StoreResult<Value> {
        Ok(Value::Blob(self.into()))
    }
}
impl Param for Vec<u8> {
    fn sql_value(&self) -> StoreResult<Value> {
        self.as_slice().sql_value()
    }
}
impl<const N: usize> Param for [u8; N] {
    fn sql_value(&self) -> StoreResult<Value> {
        self.as_slice().sql_value()
    }
}
impl<T: Param + ?Sized> Param for &T {
    fn sql_value(&self) -> StoreResult<Value> {
        (*self).sql_value()
    }
}
impl<T: Param> Param for Option<T> {
    fn sql_value(&self) -> StoreResult<Value> {
        match self {
            Some(v) => v.sql_value(),
            None => Ok(Value::Null),
        }
    }
}
pub(crate) fn param<T: Param + ?Sized>(v: &T) -> StoreResult<Value> {
    v.sql_value()
}
macro_rules! sql_params {($($v:expr),* $(,)?)=>{rusqlite::params![$(crate::sql_value::param(&$v)?),*]}}
pub(crate) use sql_params;
pub(crate) trait ReadValue: Sized {
    fn read(row: &Row<'_>, index: usize) -> rusqlite::Result<Self>;
}
macro_rules! read_native {($($t:ty),*)=>{$(impl ReadValue for $t{fn read(row:&Row<'_>,index:usize)->rusqlite::Result<Self>{row.get(index)}})*}}
read_native!(i64, u32, u16, String, Vec<u8>, bool);
impl ReadValue for u64 {
    fn read(row: &Row<'_>, index: usize) -> rusqlite::Result<Self> {
        let v: i64 = row.get(index)?;
        u64::try_from(v).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, v))
    }
}
impl<T: ReadValue> ReadValue for Option<T> {
    fn read(row: &Row<'_>, index: usize) -> rusqlite::Result<Self> {
        if matches!(row.get_ref(index)?, rusqlite::types::ValueRef::Null) {
            Ok(None)
        } else {
            T::read(row, index).map(Some)
        }
    }
}
pub(crate) fn value<T: ReadValue>(row: &Row<'_>, index: usize) -> rusqlite::Result<T> {
    T::read(row, index)
}
