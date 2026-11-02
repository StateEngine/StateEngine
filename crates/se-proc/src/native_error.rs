//! Shared standard error traits; each native adapter retains its facts and policy.
// Keep concrete structs at their call sites so field visibility and code enums
// remain unchanged. Formatting and source selection are explicit per type.
macro_rules! native_error {
    ($name:ident, |$error:ident, $out:ident| $display:expr $(; source $source:expr)? $(;)?) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, $out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let $error = self;
                $display
            }
        }
        impl std::error::Error for $name {
            $(fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                let $error = self;
                $source
            })?
        }
    };
}
pub(crate) use native_error;
