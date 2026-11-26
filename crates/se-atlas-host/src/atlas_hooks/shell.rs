//! Read the search pattern from a single `rg` or `grep` command line without
//! running a shell. Anything that could chain, redirect or substitute commands,
//! and any option not known to keep a plain case-sensitive search, is not
//! classified: an unsure reading stays silent.

/// The pattern of a plain `rg` or `grep` search, or the file of a plain `cat`.
pub(super) enum Command {
    Search(String),
    Read(String),
}

pub(super) fn command(text: &str) -> Option<Command> {
    let words = words(text)?;
    let (program, arguments) = words.split_first()?;
    match program.as_str() {
        "rg" => pattern(arguments, Program::Ripgrep).map(Command::Search),
        "grep" => pattern(arguments, Program::Grep).map(Command::Search),
        "cat" => match arguments {
            [path] if !path.starts_with('-') => Some(Command::Read(path.clone())),
            _ => None,
        },
        _ => None,
    }
}

/// Split shell words with plain single and double quotes. Operators,
/// substitutions, escapes and unterminated quotes refuse the whole line.
fn words(text: &str) -> Option<Vec<String>> {
    if text.len() > 1024 {
        return None;
    }
    let (mut words, mut word, mut started) = (Vec::new(), String::new(), false);
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            '\'' | '"' => {
                started = true;
                loop {
                    let next = characters.next()?;
                    if next == character {
                        break;
                    }
                    if character == '"' && matches!(next, '$' | '`' | '\\') {
                        return None;
                    }
                    word.push(next);
                }
            }
            ';' | '|' | '&' | '>' | '<' | '$' | '`' | '\\' | '(' | ')' | '\n' | '\r' => {
                return None;
            }
            other => {
                started = true;
                word.push(other);
            }
        }
    }
    if started {
        words.push(word);
    }
    (words.len() <= 32).then_some(words)
}

#[derive(Clone, Copy)]
enum Program {
    Ripgrep,
    Grep,
}

/// How a known option affects reading the pattern. Every option missing from
/// these lists, including ones that list files, count or invert matches, ignore
/// case or read patterns from a file, leaves the command unclassified.
#[derive(Clone, Copy, PartialEq)]
enum Arity {
    Flag,
    Value,
}

impl Program {
    fn short(self, option: char) -> Option<Arity> {
        let (flags, values) = match self {
            Self::Ripgrep => ("nNwxFHsuoLaU", "ABCEMTegjmrt"),
            Self::Grep => ("nHhwxFGEPrRsaoI", "ABCDdem"),
        };
        if flags.contains(option) {
            Some(Arity::Flag)
        } else {
            values.contains(option).then_some(Arity::Value)
        }
    }

    fn long(self, name: &str) -> Option<Arity> {
        const FLAGS: &[&str] = &[
            "line-number",
            "with-filename",
            "no-filename",
            "word-regexp",
            "line-regexp",
            "fixed-strings",
            "only-matching",
            "no-messages",
            "text",
        ];
        const VALUES: &[&str] = &[
            "after-context",
            "before-context",
            "context",
            "max-count",
            "regexp",
        ];
        const RIPGREP_FLAGS: &[&str] = &[
            "no-line-number",
            "case-sensitive",
            "hidden",
            "no-ignore",
            "follow",
            "multiline",
            "pcre2",
            "heading",
            "no-heading",
            "column",
            "no-column",
            "vimgrep",
            "trim",
            "unrestricted",
            "search-zip",
            "no-config",
        ];
        const RIPGREP_VALUES: &[&str] = &[
            "glob",
            "type",
            "type-not",
            "threads",
            "max-columns",
            "max-depth",
            "max-filesize",
            "encoding",
            "engine",
            "sort",
            "sortr",
            "color",
        ];
        const GREP_FLAGS: &[&str] = &[
            "extended-regexp",
            "basic-regexp",
            "perl-regexp",
            "recursive",
            "dereference-recursive",
            "color",
            "colour",
        ];
        const GREP_VALUES: &[&str] = &["include", "exclude", "exclude-dir"];
        let (flags, values) = match self {
            Self::Ripgrep => (RIPGREP_FLAGS, RIPGREP_VALUES),
            Self::Grep => (GREP_FLAGS, GREP_VALUES),
        };
        if FLAGS.contains(&name) || flags.contains(&name) {
            Some(Arity::Flag)
        } else {
            (VALUES.contains(&name) || values.contains(&name)).then_some(Arity::Value)
        }
    }
}

/// The one pattern a search names: the first operand, or its single `-e`.
/// Later operands are paths. Any option this reader does not know refuses.
fn pattern(arguments: &[String], program: Program) -> Option<String> {
    let (mut explicit, mut operands, mut options_end) = (None, Vec::new(), false);
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if options_end || argument == "-" || !argument.starts_with('-') {
            operands.push(argument.clone());
        } else if argument == "--" {
            options_end = true;
        } else if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            };
            match program.long(name)? {
                // grep's `--color=WHEN` is the one flag with an optional value.
                Arity::Flag if attached.is_some() && !name.starts_with("colo") => return None,
                Arity::Flag => {}
                Arity::Value => {
                    let value = match attached {
                        Some(value) => value,
                        None => arguments.next()?.clone(),
                    };
                    if name == "regexp" && explicit.replace(value).is_some() {
                        return None;
                    }
                }
            }
        } else {
            let options: Vec<char> = argument[1..].chars().collect();
            for (index, option) in options.iter().enumerate() {
                if program.short(*option)? == Arity::Value {
                    let rest: String = options[index + 1..].iter().collect();
                    let value = if rest.is_empty() {
                        arguments.next()?.clone()
                    } else {
                        rest
                    };
                    if *option == 'e' && explicit.replace(value).is_some() {
                        return None;
                    }
                    break;
                }
            }
        }
    }
    explicit.or_else(|| operands.into_iter().next())
}
