//! Compile the shared harness data; runtime consumers need no parser or allocation.
use proc_macro::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    variant: String,
    id: String,
    title: String,
    selection_title: Option<String>,
    driver: String,
    command: String,
    selection: Selection,
    omit_default_config: bool,
    seed_profile: bool,
    detached_no_approval: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Selection {
    Default,
    Builtin,
    Configured,
}

/// Apply a consumer macro to the canonical harness rows.
#[proc_macro]
pub fn with_harness_registry(consumer: TokenStream) -> TokenStream {
    match expand(consumer) {
        Ok(tokens) => tokens,
        Err(message) => [
            TokenTree::Ident(Ident::new("compile_error", Span::call_site())),
            TokenTree::Punct(Punct::new('!', Spacing::Alone)),
            TokenTree::Group(Group::new(
                Delimiter::Brace,
                TokenStream::from(TokenTree::Literal(Literal::string(&message))),
            )),
        ]
        .into_iter()
        .collect(),
    }
}

fn expand(consumer: TokenStream) -> Result<TokenStream, String> {
    let mut input = consumer.into_iter();
    let Some(TokenTree::Ident(consumer)) = input.next() else {
        return Err("expected a registry consumer macro name".into());
    };
    if input.next().is_some() {
        return Err("expected only one registry consumer macro name".into());
    }
    let rows: Vec<Entry> =
        serde_json::from_str(include_str!("registry.json")).map_err(|error| error.to_string())?;
    let mut source = format!("{consumer}! {{");
    for row in rows {
        let default = if matches!(row.selection, Selection::Default) {
            "#[default]"
        } else {
            ""
        };
        let skip = if row.omit_default_config {
            "#[serde(skip_serializing_if = \"is_default_provider\")]"
        } else {
            ""
        };
        source.push_str(&format!(
            "{} {} [{}] [{}] {{ id: {:?}, title: {:?}, selection_title: {:?}, driver: {:?}, command: {:?}, \
             selectable: {}, seed_profile: {}, detached_no_approval: {} }};\n",
            row.variant,
            row.id,
            default,
            skip,
            row.id,
            row.title,
            row.selection_title.as_deref().unwrap_or(&row.title),
            row.driver,
            row.command,
            !matches!(row.selection, Selection::Configured),
            row.seed_profile,
            row.detached_no_approval,
        ));
    }
    source.push('}');
    source
        .parse()
        .map_err(|error| format!("invalid harness registration: {error}"))
}
