//! Mechanical test-hygiene guards, enforced in CI.
//!
//! Two 2026-11-18 rulings, made mechanical: the count of fixed-sleep call sites under
//! `crates/*/tests` may not grow past the checked-in ceiling, and a new wait must use a
//! real signal instead of a fixed delay. Every `#[ignore]` in the workspace must carry
//! its reason using Rust's built-in `#[ignore = "why"]` form; a bare `#[ignore]` refuses.
//!
//! Both checks parse each file with `syn`, the maintained Rust parser, so comments and
//! every string, raw string, C string, and char literal form are opaque to the rules, and
//! `use` imports resolve within their module scope: grouped and aliased imports count
//! their bare calls, an import inside one module never binds another, and a local item
//! named `sleep` shadows any import. A macro body is a token stream the parser does not
//! walk, so a sleep call in one, such as a `tokio::select!` arm, is matched by its token
//! pattern on the lexer's own output. A file that does not parse is a failure, named.

use proc_macro2::{Delimiter, TokenTree};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, File, Item, Meta, UseTree, visit};

/// Checked-in ceiling for fixed-sleep call sites under `crates/*/tests`, counted 2026-11-18
/// on main bbec2cfa5 with the syn-based scanner. It may only go down: when you remove
/// fixed sleeps, lower it to the new total.
const MAX_FIXED_TEST_SLEEPS: usize = 109;

fn workspace_root() -> PathBuf {
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => fs::canonicalize(Path::new(&dir).join("../..")).unwrap_or_else(|error| {
            panic!("test-hygiene-rules: cannot resolve the workspace root from {dir}: {error}")
        }),
        Err(_) => panic!("test-hygiene-rules: CARGO_MANIFEST_DIR is not set; run through cargo"),
    }
}

fn collect_rs(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Every `.rs` file under `crates/*/src` and/or `crates/*/tests`, in a stable order.
fn crate_trees(crates_dir: &Path, trees: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(crate_dirs) = fs::read_dir(crates_dir) else {
        return files;
    };
    for crate_dir in crate_dirs.flatten() {
        if !crate_dir.path().is_dir() {
            continue;
        }
        for tree in trees {
            collect_rs(&crate_dir.path().join(tree), &mut files);
        }
    }
    files.sort();
    files
}

fn read_source(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "test-hygiene-rules: cannot read {}: {}",
            path.display(),
            error
        )
    });
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A module's name bindings, as far as these guards care.
#[derive(Clone, Default)]
struct ModuleScope {
    /// A name bound by an explicit `use` in this module; true when the imported path ends
    /// in `thread::sleep` or `time::sleep`.
    imports: HashMap<String, bool>,
    /// Whether each glob `use` imports from a module named `thread` or `time`.
    globs: Vec<bool>,
    /// Names declared as items in this module; they shadow imports from outer modules.
    locals: HashSet<String>,
}

fn is_sleep_binding(segments: &[String]) -> bool {
    segments.len() >= 2
        && matches!(
            (
                segments[segments.len() - 2].as_str(),
                segments[segments.len() - 1].as_str()
            ),
            ("thread", "sleep") | ("time", "sleep")
        )
}

fn collect_use(tree: &UseTree, prefix: &mut Vec<String>, scope: &mut ModuleScope) {
    match tree {
        UseTree::Path(use_path) => {
            prefix.push(use_path.ident.to_string());
            collect_use(&use_path.tree, prefix, scope);
        }
        UseTree::Name(use_name) => {
            let mut full = prefix.clone();
            full.push(use_name.ident.to_string());
            scope
                .imports
                .insert(use_name.ident.to_string(), is_sleep_binding(&full));
        }
        UseTree::Rename(use_rename) => {
            let mut full = prefix.clone();
            full.push(use_rename.ident.to_string());
            scope
                .imports
                .insert(use_rename.rename.to_string(), is_sleep_binding(&full));
        }
        UseTree::Glob(_) => {
            scope.globs.push(matches!(
                prefix.last().map(String::as_str),
                Some("thread") | Some("time")
            ));
        }
        UseTree::Group(use_group) => {
            for tree in &use_group.items {
                collect_use(tree, prefix, scope);
            }
        }
    }
}

fn item_name(item: &Item) -> Option<String> {
    match item {
        Item::Fn(fn_item) => Some(fn_item.sig.ident.to_string()),
        Item::Struct(struct_item) => Some(struct_item.ident.to_string()),
        Item::Enum(enum_item) => Some(enum_item.ident.to_string()),
        Item::Trait(trait_item) => Some(trait_item.ident.to_string()),
        Item::Type(type_item) => Some(type_item.ident.to_string()),
        Item::Const(const_item) => Some(const_item.ident.to_string()),
        Item::Static(static_item) => Some(static_item.ident.to_string()),
        Item::Union(union_item) => Some(union_item.ident.to_string()),
        Item::Mod(mod_item) => Some(mod_item.ident.to_string()),
        _ => None,
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Fn(fn_item) => &fn_item.attrs,
        Item::Const(const_item) => &const_item.attrs,
        Item::Static(static_item) => &static_item.attrs,
        Item::Struct(struct_item) => &struct_item.attrs,
        Item::Enum(enum_item) => &enum_item.attrs,
        Item::Union(union_item) => &union_item.attrs,
        Item::Trait(trait_item) => &trait_item.attrs,
        Item::TraitAlias(trait_alias_item) => &trait_alias_item.attrs,
        Item::Type(type_item) => &type_item.attrs,
        Item::Mod(mod_item) => &mod_item.attrs,
        Item::ForeignMod(foreign_mod) => &foreign_mod.attrs,
        Item::Impl(impl_item) => &impl_item.attrs,
        Item::Use(use_item) => &use_item.attrs,
        Item::Macro(macro_item) => &macro_item.attrs,
        // syn::Item is non-exhaustive; an unknown item form carries no checkable attrs.
        _ => &[],
    }
}

/// Every call site in an item, as (callee path segment names, line).
struct CallFinder {
    sites: Vec<(Vec<String>, usize)>,
    /// The module scope chain in effect where the visited item sits, used to resolve
    /// bare `sleep` calls inside macro bodies.
    chain: Vec<ModuleScope>,
}

impl<'ast> Visit<'ast> for CallFinder {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Call(call) = expr
            && let Expr::Path(path) = &*call.func
        {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let line = path.path.span().start().line;
            self.sites.push((segments, line));
        }
        visit::visit_expr(self, expr);
    }

    fn visit_token_stream(&mut self, tokens: &'ast proc_macro2::TokenStream) {
        count_macro_body(tokens, &self.chain, &mut self.sites);
    }
}

#[derive(Debug)]
/// A significant token of a macro body, in order.
enum SigTok {
    /// An identifier, with the line it starts on.
    Ident(String, usize),
    /// A `::` pair, spaced or not.
    ColonColon,
    /// A parenthesized group; the only group kind a call can follow.
    ParenGroup,
    /// Anything else: punct, literals, brace and bracket groups.
    Other,
}

fn sig_tokens(stream: &proc_macro2::TokenStream, out: &mut Vec<SigTok>) {
    let mut maybe_colon = false;
    for token in stream.clone() {
        if maybe_colon {
            match token {
                TokenTree::Punct(punct) if punct.as_char() == ':' => {
                    out.push(SigTok::ColonColon);
                    maybe_colon = false;
                    continue;
                }
                _ => {
                    out.push(SigTok::Other);
                    maybe_colon = false;
                    continue;
                }
            }
        }
        match token {
            TokenTree::Punct(punct) if punct.as_char() == ':' => {
                maybe_colon = true;
            }
            TokenTree::Punct(_) => out.push(SigTok::Other),
            TokenTree::Ident(ident) => {
                out.push(SigTok::Ident(ident.to_string(), ident.span().start().line))
            }
            TokenTree::Literal(_) => out.push(SigTok::Other),
            TokenTree::Group(group) => {
                if group.delimiter() == Delimiter::Parenthesis {
                    out.push(SigTok::ParenGroup);
                } else if group.delimiter() == Delimiter::None {
                    sig_tokens(&group.stream(), out);
                } else {
                    out.push(SigTok::Other);
                }
            }
        }
    }
    if maybe_colon {
        out.push(SigTok::Other);
    }
}

fn sleep_in_macro(sig: &[SigTok], chain: &[ModuleScope], sites: &mut Vec<(Vec<String>, usize)>) {
    for (i, tok) in sig.iter().enumerate() {
        if !matches!(tok, SigTok::ParenGroup) || i == 0 {
            continue;
        }
        let Some(SigTok::Ident(name, line)) = sig.get(i - 1) else {
            continue;
        };
        if name != "sleep" {
            continue;
        }
        let path_form = i >= 2 && matches!(sig.get(i - 2), Some(SigTok::ColonColon));
        if !path_form {
            // A bare `sleep(` resolves only through this module's scope chain.
            if resolves_to_sleep(&["sleep".to_string()], chain) {
                sites.push((vec!["sleep".to_string()], *line));
            }
            continue;
        }
        // `::sleep(`: a path form. Only `...::thread::sleep(` or `...::time::sleep(`
        // is a fixed wait; anything else, like `foo::sleep(`, is not.
        if i < 3 {
            continue;
        }
        let Some(SigTok::Ident(mid, _)) = sig.get(i - 3) else {
            continue;
        };
        if mid != "thread" && mid != "time" {
            continue;
        }
        // Walk outward from `mid`; prefixes come back innermost-first, so reverse
        // into source order before appending `sleep`.
        let mut segments = vec![mid.clone()];
        let mut pos = i - 3;
        while pos >= 2
            && matches!(sig.get(pos - 1), Some(SigTok::ColonColon))
            && matches!(sig.get(pos - 2), Some(SigTok::Ident(_, _)))
        {
            if let Some(SigTok::Ident(prefix, _)) = sig.get(pos - 2) {
                segments.push(prefix.clone());
            }
            pos -= 2;
        }
        segments.reverse();
        segments.push("sleep".to_string());
        sites.push((segments, *line));
    }
}

fn count_macro_body(
    tokens: &proc_macro2::TokenStream,
    chain: &[ModuleScope],
    sites: &mut Vec<(Vec<String>, usize)>,
) {
    let mut sig = Vec::new();
    sig_tokens(tokens, &mut sig);
    sleep_in_macro(&sig, chain, sites);
    for token in tokens.clone() {
        if let TokenTree::Group(group) = token
            && group.delimiter() != Delimiter::None
        {
            count_macro_body(&group.stream(), chain, sites);
        }
    }
}

fn resolves_to_sleep(segments: &[String], chain: &[ModuleScope]) -> bool {
    if segments.len() >= 2 {
        return is_sleep_binding(segments);
    }
    let name = &segments[0];
    for scope in chain.iter().rev() {
        if scope.locals.contains(name) {
            return false; // a local item shadows any import; a local `sleep` is not std's
        }
        if let Some(is_sleep) = scope.imports.get(name) {
            return *is_sleep;
        }
    }
    chain
        .iter()
        .rev()
        .any(|scope| name == "sleep" && scope.globs.iter().any(|and_provides| *and_provides))
}

#[derive(Default)]
struct FileReport {
    sleeps: Vec<(String, usize)>,
    bare_ignores: Vec<usize>,
}

fn check_attributes(attrs: &[Attribute], report: &mut FileReport) {
    for attr in attrs {
        if attr.path().is_ident("ignore") && matches!(attr.meta, Meta::Path(_)) {
            report.bare_ignores.push(attr.span().start().line);
        }
    }
}

fn scan_items(items: &[Item], chain: Vec<ModuleScope>, report: &mut FileReport) {
    let mut scope = ModuleScope::default();
    for item in items {
        if let Item::Use(use_item) = item {
            collect_use(&use_item.tree, &mut Vec::new(), &mut scope);
        }
        if let Some(name) = item_name(item) {
            scope.locals.insert(name);
        }
    }
    for item in items {
        check_attributes(item_attrs(item), report);
        let item_chain = {
            let mut extended = chain.clone();
            extended.push(scope.clone());
            extended
        };
        match item {
            Item::Mod(mod_item) => {
                if let Some((_, inner)) = &mod_item.content {
                    scan_items(inner, item_chain.clone(), report);
                }
            }
            Item::Impl(impl_item) => {
                for impl_item in &impl_item.items {
                    if let syn::ImplItem::Fn(fn_item) = impl_item {
                        check_attributes(&fn_item.attrs, report);
                    }
                }
            }
            _ => {}
        }
        // A braced mod was already scanned in its own scope above; everything else,
        // including a bare `mod x;` with no body, is visited here.
        if !matches!(item, Item::Mod(mod_item) if mod_item.content.is_some()) {
            let mut finder = CallFinder {
                sites: Vec::new(),
                chain: item_chain.clone(),
            };
            visit::visit_item(&mut finder, item);
            for (segments, line) in finder.sites {
                if resolves_to_sleep(&segments, &item_chain) {
                    report.sleeps.push((segments.join("::"), line));
                }
            }
        }
    }
}

fn report_of(source: &str) -> FileReport {
    let file: File = syn::parse_str(source)
        .unwrap_or_else(|error| panic!("test-hygiene-rules: cannot parse the source: {error}"));
    let mut report = FileReport::default();
    scan_items(&file.items, Vec::new(), &mut report);
    report
}

fn report_of_path(path: &Path) -> FileReport {
    let source = read_source(path);
    let file: File = syn::parse_str(&source).unwrap_or_else(|error| {
        panic!(
            "test-hygiene-rules: cannot parse {}: {error}",
            path.display()
        )
    });
    let mut report = FileReport::default();
    scan_items(&file.items, Vec::new(), &mut report);
    report
}

#[test]
fn fixed_test_sleeps_may_only_go_down() {
    let crates_dir = workspace_root().join("crates");
    let mut total = 0usize;
    let mut offenders: Vec<(PathBuf, Vec<(String, usize)>)> = Vec::new();
    for path in crate_trees(&crates_dir, &["tests"]) {
        let report = report_of_path(&path);
        if !report.sleeps.is_empty() {
            total += report.sleeps.len();
            offenders.push((path, report.sleeps));
        }
    }
    if total > MAX_FIXED_TEST_SLEEPS {
        let mut message = format!(
            "test-hygiene-rules: fixed test sleeps at {total}, above the checked-in ceiling of {}.\n",
            MAX_FIXED_TEST_SLEEPS
        );
        for (path, sites) in &offenders {
            message.push_str(&format!("{}\n", path.display()));
            for (callee, line) in sites {
                message.push_str(&format!("  {line}: {callee}(...)\n"));
            }
        }
        message.push_str(
            "A new fixed wait must use a real signal instead of a delay; lower the ceiling \
             only after removing sleeps, and recount it.\n",
        );
        panic!("{message}");
    }
}

#[test]
fn every_ignored_test_carries_a_reason() {
    let crates_dir = workspace_root().join("crates");
    let mut offenders: Vec<(PathBuf, Vec<usize>)> = Vec::new();
    for path in crate_trees(&crates_dir, &["src", "tests"]) {
        let report = report_of_path(&path);
        if !report.bare_ignores.is_empty() {
            offenders.push((path, report.bare_ignores));
        }
    }
    if !offenders.is_empty() {
        let mut message =
            String::from("test-hygiene-rules: a bare #[ignore] without a reason refuses.\n");
        for (path, lines) in &offenders {
            message.push_str(&format!("{}\n", path.display()));
            for line in lines {
                message.push_str(&format!("  {line}: #[ignore]\n"));
            }
        }
        message.push_str("Give it its reason: #[ignore = \"why\"].\n");
        panic!("{message}");
    }
}

#[cfg(test)]
mod scanner_controls {
    use super::*;

    const CALL: &str = "    std::thread::sleep(std::time::Duration::ZERO);\n";

    fn fixture(body: &str, prefix: &str) -> String {
        format!("{prefix}#[test]\nfn fixture() {{\n{body}}}\n")
    }

    fn sleep_count(src: &str) -> usize {
        report_of(src).sleeps.len()
    }

    fn ignore_lines(src: &str) -> Vec<usize> {
        report_of(src).bare_ignores
    }

    #[test]
    fn control_sleep_at_ceiling_is_exact() {
        let src = fixture(&CALL.repeat(MAX_FIXED_TEST_SLEEPS), "");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_one_real_call_over() {
        let src = fixture(&CALL.repeat(MAX_FIXED_TEST_SLEEPS + 1), "");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_sleep_in_comment_is_not_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    // std::thread::sleep(std::time::Duration::ZERO);\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_sleep_in_string_is_not_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS) + "    let _ = \"tokio::time::sleep(...)\";\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_sleep_in_import_is_not_counted() {
        let src = fixture(
            CALL.repeat(MAX_FIXED_TEST_SLEEPS).as_str(),
            "#[allow(unused_imports)]\nuse std::thread::sleep;\n",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_empty_string_keeps_the_scan_in_sync() {
        let src =
            "fn f() {\n    let _ = \"\";\n    std::thread::sleep(std::time::Duration::ZERO);\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_escaped_quote_start_keeps_the_scan_in_sync() {
        let src = "fn f() {\n    let _ = \"\\\"quoted\\\"\";\n    std::thread::sleep(std::time::Duration::ZERO);\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_spaced_real_call_is_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    std :: thread :: sleep(std::time::Duration::ZERO);\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_imported_calls_are_counted() {
        let body = CALL.repeat(MAX_FIXED_TEST_SLEEPS - 1)
            + "    sleep(std::time::Duration::ZERO);\n    sleep(std::time::Duration::ZERO);\n";
        let src = fixture(&body, "use std::thread::sleep;\n");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_grouped_import_is_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    sleep(std::time::Duration::ZERO);\n    yield_now();\n"),
            "use std::thread::{sleep, yield_now};\n",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_aliased_import_is_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS) + "    delay(std::time::Duration::ZERO);\n"),
            "use std::thread::sleep as delay;\n",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_comment_between_call_tokens_is_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    std::thread::sleep /* a comment */ (std::time::Duration::ZERO);\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_import_in_unrelated_module_does_not_count() {
        let prefix = "mod a { #[allow(unused_imports)] use std::thread::sleep; }\nmod b { #[allow(dead_code)] fn sleep() {} }\n";
        let src = fixture(&CALL.repeat(MAX_FIXED_TEST_SLEEPS), prefix);
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_local_sleep_declaration_is_not_counted() {
        let src = "mod m { #[allow(dead_code)] fn sleep() {}\n    #[test]\n    fn fixture() { sleep(); }\n}\n";
        assert_eq!(sleep_count(src), 0);
    }

    #[test]
    fn control_reasoned_ignore_passes() {
        let src = "#[test]\n#[ignore = \"requires a dedicated runner\"]\nfn sample() {}\n";
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_literal_bare_ignore_is_found() {
        let src = "#[test]\n#[ignore]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_formatted_bare_ignore_is_found() {
        let src = "#[test]\n#[ignore ]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_multiline_bare_ignore_is_found() {
        let src = "#[test]\n#[\n    ignore\n]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_comment_between_ignore_tokens_is_found() {
        let src = "#[test]\n#[ignore /* a Rust comment is whitespace */]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_ignore_in_raw_string_is_not_found() {
        let src = "#[test]\nfn sample() { let _ = r#\"\n#[ignore]\n\"#; }\n";
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_raw_c_string_is_opaque_to_sleep_scan() {
        let src = format!(
            "fn f() {{\n{}    let _ = cr#\"embedded quote \" and std::thread::sleep(...)\"#;\n}}\n",
            CALL.repeat(MAX_FIXED_TEST_SLEEPS)
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_raw_c_string_cannot_break_ignore_scan() {
        let src = "#[test]\n#[ignore = \"isolated runner needed\"]\nfn fixture() {\n    let _ = cr#\"embedded quote \" and #[ignore]\"#;\n}\n";
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_lexer_edges_stay_opaque() {
        let src = "fn f() {\n/* thread::sleep( /* nested */ still a comment) */\n\
                   let a = \"/* not a comment \\\" quoted\";\n\
                   let b = '(';\nlet c = 'x';\n}\nfn g<'a>(_: &'a u8) {}\n";
        assert_eq!(sleep_count(src), 0);
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_sleep_in_macro_body_is_counted() {
        let src = "fn f() {\n    wait! { _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {} }\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_bare_sleep_in_macro_body_uses_scope() {
        let src = "use std::thread::sleep;\nfn f() {\n    wait! { _ = sleep(std::time::Duration::from_secs(1)) => {} }\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_local_shadow_in_macro_body_is_not_counted() {
        let src = "mod m { #[allow(dead_code)] fn sleep() {}\n    #[allow(unused)] fn f() { wait! { _ = sleep(1) => {} } }\n}\n";
        assert_eq!(sleep_count(src), 0);
    }
}
