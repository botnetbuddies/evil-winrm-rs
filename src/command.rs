use anyhow::{Result, bail};
use psrp_rs::{Command, Pipeline, PsValue};

pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Debug, PartialEq)]
pub enum Token {
    Word(String),
    Pipe,
    Statement,
}

/// PowerShell-style lexical quoting. Backslashes in Windows paths are literal.
/// Separators inside quotes remain part of an argument, including empty strings.
pub fn tokenize(line: &str, separators: bool) -> Result<Vec<Token>> {
    let mut chars = line.chars().peekable();
    let mut out = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => {
                if q == '\'' && chars.peek() == Some(&'\'') {
                    word.push(chars.next().unwrap());
                } else {
                    quote = None;
                }
            }
            Some('"') if c == '`' => {
                let escaped = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("incomplete escape"))?;
                if escaped == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                } else if escaped != '\n' {
                    word.push(escaped);
                }
            }
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                started = true;
            }
            None if c.is_whitespace() || (separators && matches!(c, '|' | ';')) => {
                if started {
                    out.push(Token::Word(std::mem::take(&mut word)));
                    started = false;
                }
                if c == '|' && separators {
                    out.push(Token::Pipe);
                }
                if c == ';' && separators {
                    out.push(Token::Statement);
                }
                if c == '\n'
                    && separators
                    && !matches!(out.last(), Some(Token::Pipe | Token::Statement))
                    && chars.clone().find(|c| !c.is_whitespace()) != Some('|')
                {
                    out.push(Token::Statement);
                }
            }
            None if c == '`' => {
                let escaped = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("incomplete escape"))?;
                if escaped == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                } else if escaped != '\n' {
                    started = true;
                    word.push(escaped);
                }
            }
            None => {
                started = true;
                word.push(c);
            }
        }
    }
    if quote.is_some() {
        bail!("unclosed quote");
    }
    if started {
        out.push(Token::Word(word));
    }
    Ok(out)
}

pub fn arguments(line: &str) -> Result<Vec<String>> {
    Ok(tokenize(line, false)?
        .into_iter()
        .filter_map(|t| {
            if let Token::Word(w) = t {
                Some(w)
            } else {
                None
            }
        })
        .collect())
}

fn parameter(word: &str) -> bool {
    word.strip_prefix('-')
        .is_some_and(|s| s.chars().next().is_some_and(|c| c.is_alphabetic()))
}

pub fn jea_pipelines(line: &str) -> Result<Vec<Pipeline>> {
    let tokens = tokenize(line, true)?;
    if matches!(tokens.last(), Some(Token::Pipe)) {
        bail!("incomplete pipeline");
    }
    let mut words = Vec::new();
    let mut pipeline = Pipeline::empty();
    let mut pipelines = Vec::new();
    for token in tokens.into_iter().chain([Token::Statement]) {
        if let Token::Word(w) = token {
            words.push(w);
            continue;
        }
        if !words.is_empty() {
            let mut command = Command::new(&words[0]);
            let mut i = 1;
            while i < words.len() {
                let word = &words[i];
                if parameter(word) {
                    if let Some((name, value)) = word[1..].split_once(':') {
                        let value = match value.to_ascii_lowercase().as_str() {
                            "$true" => PsValue::Bool(true),
                            "$false" => PsValue::Bool(false),
                            _ => PsValue::String(value.into()),
                        };
                        command = command.with_parameter(name, value);
                    } else if i + 1 < words.len() && !parameter(&words[i + 1]) {
                        command = command
                            .with_parameter(&word[1..], PsValue::String(words[i + 1].clone()));
                        i += 1;
                    } else {
                        command = command.with_switch(&word[1..]);
                    }
                } else {
                    command = command.with_argument(PsValue::String(word.clone()));
                }
                i += 1;
            }
            pipeline = pipeline.add_command(command);
            words.clear();
        } else if matches!(token, Token::Pipe) {
            bail!("empty pipeline stage");
        }
        if matches!(token, Token::Statement) && !pipeline.is_empty() {
            pipelines.push(pipeline);
            pipeline = Pipeline::empty();
        }
    }
    Ok(pipelines)
}

pub fn interactive_pipeline(line: &str) -> Pipeline {
    Pipeline::empty()
        .add_command(
            Command::new("Invoke-Expression")
                .with_parameter("Command", PsValue::String(line.into())),
        )
        .add_command(Command::new("Out-String").with_switch("Stream"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_backticks_pipelines_and_windows_paths() {
        for newline in ["\n", "\r\n"] {
            assert_eq!(
                arguments(&format!(
                    "upload `{newline} 'C:\\a file.txt' `{newline} 'D:\\out.txt'"
                ))
                .unwrap(),
                ["upload", r"C:\a file.txt", r"D:\out.txt"]
            );
            assert_eq!(
                jea_pipelines(&format!("Get-Command |{newline} Select-Object Name")).unwrap()[0]
                    .len(),
                2
            );
            assert_eq!(
                jea_pipelines(&format!("Get-Command{newline}| Select-Object Name")).unwrap()[0]
                    .len(),
                2
            );
            assert_eq!(
                jea_pipelines(&format!("Write-Output first{newline}Write-Output second"))
                    .unwrap()
                    .len(),
                2
            );
        }
        assert!(jea_pipelines("Get-Command |").is_err());
    }
    #[test]
    fn windows_paths_and_empty_arguments_survive() {
        assert_eq!(
            arguments(r#"upload "C:\Program Files\a.txt" 'C:\O''Brien\a.txt' ''"#).unwrap(),
            [
                "upload",
                "C:\\Program Files\\a.txt",
                "C:\\O'Brien\\a.txt",
                ""
            ]
        );
    }
    #[test]
    fn quoted_separators_are_data() {
        assert_eq!(
            tokenize("Write-Output 'a|b;c' | Measure-Object", true).unwrap(),
            vec![
                Token::Word("Write-Output".into()),
                Token::Word("a|b;c".into()),
                Token::Pipe,
                Token::Word("Measure-Object".into())
            ]
        );
    }
    #[test]
    fn jea_statements_are_separate_structured_pipelines() {
        let p =
            jea_pipelines("Get-Service -Name Spooler | Measure-Object; Get-Command -All").unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].len(), 2);
        assert_eq!(p[1].len(), 1);
    }
    #[test]
    fn incomplete_quotes_rejected() {
        assert!(arguments("upload 'abc").is_err());
    }
    #[test]
    fn paths_cannot_escape_powershell_literal() {
        assert_eq!(
            quote("a'; Remove-Item C:\\*; '"),
            "'a''; Remove-Item C:\\*; '''"
        );
    }
}
