use crate::{lifecycle::*, model::*};
#[derive(Clone, Copy)]
pub(super) enum Binding {
    Symbol(SymbolId),
    Import(usize),
    Missing,
    Ambiguous,
}
pub(super) fn lookup(file: &ParsedFile, mut scope: u32, name: &str, at: u64) -> Binding {
    for _ in 0..128 {
        let mut binding = Binding::Missing;
        for symbol in &file.symbols {
            if symbol.lexical_scope == scope
                && symbol.name == name
                && !matches!(
                    symbol.kind,
                    SymbolKind::Method | SymbolKind::Field | SymbolKind::EnumVariant
                )
                && !(symbol.kind == SymbolKind::Module && symbol.parent.is_none())
            {
                if file.imports.iter().any(|i| {
                    !i.reexport
                        && i.lexical_scope == scope
                        && i.local_name.as_deref() == Some(name)
                        && i.span == symbol.span
                }) {
                    continue;
                }
                // Never resolve a use through a later variable/parameter binding.
                // A later binding still shadows outer/imported names, so refuse.
                if symbol.span.start_byte > at
                    && matches!(symbol.kind, SymbolKind::Variable | SymbolKind::Parameter)
                {
                    return Binding::Ambiguous;
                }
                if !matches!(binding, Binding::Missing) {
                    return Binding::Ambiguous;
                }
                binding = Binding::Symbol(symbol.id);
            }
        }
        for (index, import) in file.imports.iter().enumerate() {
            if !import.reexport
                && import.lexical_scope == scope
                && import.local_name.as_deref() == Some(name)
            {
                if !matches!(binding, Binding::Missing) {
                    return Binding::Ambiguous;
                }
                binding = Binding::Import(index);
            }
        }
        if !matches!(binding, Binding::Missing) {
            return binding;
        }
        let Some(parent) = file.scopes.get(scope as usize).and_then(|s| s.parent) else {
            return Binding::Missing;
        };
        scope = parent;
    }
    Binding::Ambiguous
}
