//! Go outline rules: functions, receiver methods attached to their type,
//! type declarations and single top-level `var`/`const` bindings.
use super::outline::{Decl, Scope, SymbolKind, ident, skip_group};

pub(crate) fn classify(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let (word, after) = split_word(header);
    let after = after.trim_start();
    match word {
        "func" => func(after),
        "type" if scope.top_level => type_decl(after),
        "var" if scope.top_level => binding(after, SymbolKind::Variable),
        "const" if scope.top_level => binding(after, SymbolKind::Const),
        _ => None,
    }
}

fn exported(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}

fn func(after: &str) -> Option<Decl> {
    if !after.starts_with('(') {
        let name = ident(after);
        return Decl::new(name, SymbolKind::Function, exported(name));
    }
    let rest = skip_group(after, b'(', b')');
    let receiver = after[1..after.len() - rest.len()].trim_end_matches(')');
    let owner = receiver
        .split_whitespace()
        .last()
        .map(|ty| ident(ty.trim_start_matches('*')))
        .unwrap_or("");
    let name = ident(rest.trim_start());
    let mut decl = Decl::new(name, SymbolKind::Method, exported(name))?;
    decl.owner = (!owner.is_empty()).then(|| owner.to_owned());
    Some(decl)
}

fn type_decl(after: &str) -> Option<Decl> {
    let name = ident(after);
    let mut rest = after[name.len()..].trim_start();
    if rest.starts_with('[') {
        rest = skip_group(rest, b'[', b']').trim_start();
    }
    let kind = match split_word(rest).0 {
        "struct" => SymbolKind::Struct,
        "interface" => SymbolKind::Interface,
        _ => SymbolKind::Type,
    };
    Decl::new(name, kind, exported(name))
}

fn binding(after: &str, kind: SymbolKind) -> Option<Decl> {
    let name = ident(after);
    Decl::new(name, kind, exported(name))
}

fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    (&text[..end], &text[end..])
}
