/// Result of evaluating a C preprocessor line (`#if`, `#elif`, `<File Expression="...">`)
/// with 100% parity to `ET9300Utilities.ET9300Project.CodeGenerator.SrcCodeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrcCodeType {
    Unmanaged = 0,
    Unknown = 1,
    Active = 2,
    Inactive = 3,
    Unexpected = 4,
}

/// Normalize a C source line or preprocessor expression with exact parity to
/// `CodeGenerator::NormalizeLine(InLine, bDeleteComments, bDeleteAllWhitespaces)`.
pub fn normalize_line(
    in_line: &str,
    delete_comments: bool,
    delete_all_whitespaces: bool,
) -> String {
    let mut owned: String;
    let work: &str = if delete_comments
        && (in_line.contains("//") || in_line.contains("/*") || in_line.contains("*/"))
    {
        owned = in_line.to_string();
        if let Some(idx) = owned.find("//") {
            if idx == 0 {
                return String::new();
            }
            owned.truncate(idx);
            if owned.is_empty() {
                return String::new();
            }
        }
        while let Some(idx) = owned.find("/*") {
            if let Some(rel_end) = owned[idx + 2..].find("*/") {
                let end = idx + 2 + rel_end;
                owned.replace_range(idx..end + 2, " ");
            } else {
                owned.truncate(idx);
                break;
            }
        }
        if let Some(idx) = owned.find("*/") {
            owned.drain(..idx + 2);
        }
        &owned
    } else {
        in_line
    };

    let mut collapsed = String::with_capacity(work.len());
    if delete_all_whitespaces {
        for ch in work.chars() {
            if ch != ' ' && ch != '\t' {
                collapsed.push(ch);
            }
        }
    } else {
        let mut prev_space = true;
        for ch in work.chars() {
            if ch == ' ' || ch == '\t' {
                if !prev_space {
                    collapsed.push(' ');
                    prev_space = true;
                }
            } else {
                prev_space = false;
                collapsed.push(ch);
            }
        }
        if collapsed.ends_with(' ') {
            collapsed.pop();
        }
    }

    if collapsed.starts_with(char::is_whitespace) || collapsed.ends_with(char::is_whitespace) {
        collapsed.trim().to_string()
    } else {
        collapsed
    }
}

/// Evaluate `[Key:<setting>]` and `[GetStrLen:<setting>]` value expressions with exact parity to
/// `ET9300Utilities.ET9300Project.ValueExpression::GetValue`.
///
/// Returns `None` when `[Key:...]` references a setting name that does not exist.
pub fn resolve_value_expression<'a, F>(
    input: &str,
    mut lookup: F,
    esi_value: bool,
) -> Option<String>
where
    F: FnMut(&str) -> Option<&'a str>,
{
    if input.is_empty() {
        return Some(String::new());
    }

    // Greedy `[Key:(?<setting>.*)]`
    if let Some(start) = input.find("[Key:") {
        let after_prefix = start + "[Key:".len();
        if let Some(rel_end) = input[after_prefix..].rfind(']') {
            let end = after_prefix + rel_end;
            let key = &input[after_prefix..end];
            let replacement = lookup(key)?;
            let mut out = String::with_capacity(input.len() + replacement.len());
            out.push_str(&input[..start]);
            out.push_str(replacement);
            out.push_str(&input[end + 1..]);
            return Some(out);
        }
    }

    // Greedy `[GetStrLen:(?<string>.*)]` — note that Beckhoff's `ValueExpression::GetValue`
    // overwrites the entire return string with `#x<HEX>` / `0x<HEX>` (ignoring any `"0x"` prefix
    // in `<DefaultValues default="0x[GetStrLen:DEVICE_NAME]">`)!
    if let Some(start) = input.find("[GetStrLen:") {
        let after_prefix = start + "[GetStrLen:".len();
        if let Some(rel_end) = input[after_prefix..].rfind(']') {
            let end = after_prefix + rel_end;
            let key = &input[after_prefix..end];
            let target = lookup(key)?;
            let utf16_len = target.encode_utf16().count();
            return Some(if esi_value {
                format!("#x{utf16_len:X}")
            } else {
                format!("0x{utf16_len:X}")
            });
        }
    }

    Some(input.to_string())
}

/// Compute `SrcCodeType` for a normalized `#if` / `#elif` / `<File Expression="...">` string,
/// matching `CodeGenerator::ComputeCompilerCommand`.
pub fn compute_compiler_command<S, F>(norm_line: &str, lookup: F) -> SrcCodeType
where
    S: AsRef<str>,
    F: FnMut(&str) -> Option<S>,
{
    let expr = norm_line
        .replace("#ifndef", "")
        .replace("#if", "")
        .replace("#elif", "");
    match evaluate_raw_expression(&expr, lookup) {
        EvalOutcome::Value(n) => {
            if n != 0 {
                SrcCodeType::Active
            } else {
                SrcCodeType::Inactive
            }
        }
        EvalOutcome::UnknownDefine => SrcCodeType::Unknown,
        EvalOutcome::SyntaxError => SrcCodeType::Unexpected,
    }
}

/// Evaluate a boolean setting expression (`<Value Expression="...">`, `<SettingConflict>`,
/// `<ESI><Value ActiveExpression="...">`, `UpdateInformation.xml`), matching
/// `CodeGenerator::EvaluateBooleanExpression`.
pub fn evaluate_boolean_expression<S, F>(expression: &str, lookup: F) -> bool
where
    S: AsRef<str>,
    F: FnMut(&str) -> Option<S>,
{
    matches!(
        evaluate_raw_expression(expression, lookup),
        EvalOutcome::Value(n) if n != 0
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalOutcome {
    Value(i64),
    UnknownDefine,
    SyntaxError,
}

/// Substitute defines using Beckhoff's exact identifier rule `(?<define>[A-Z|_][A-Za-z0-9_]+)`
/// and evaluate arithmetic/relational/logical operators.
pub fn evaluate_raw_expression<S, F>(expression: &str, mut lookup: F) -> EvalOutcome
where
    S: AsRef<str>,
    F: FnMut(&str) -> Option<S>,
{
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return EvalOutcome::SyntaxError;
    }

    let bytes = trimmed.as_bytes();
    let mut substituted = String::with_capacity(trimmed.len() + 16);
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        // Match `||` as logical OR operator when NOT immediately followed by `[A-Za-z0-9_]`
        // (matching C# regex `[A-Z|_][A-Za-z0-9_]+` behavior!)
        if b == b'|'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'|'
            && (i + 2 >= bytes.len() || !is_ident_continue(bytes[i + 2]))
        {
            substituted.push_str("||");
            i += 2;
            continue;
        }

        if is_beckhoff_ident_start(b) && i + 1 < bytes.len() && is_ident_continue(bytes[i + 1]) {
            let start = i;
            i += 2;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let ident = trimmed[start..i].trim();
            let Some(val_raw) = lookup(ident) else {
                return EvalOutcome::UnknownDefine;
            };
            let val = val_raw.as_ref();
            let coerced = if val.is_empty() || val == "0" || val == "0x0" {
                "0"
            } else {
                "1"
            };
            substituted.push_str(coerced);
        } else {
            substituted.push(b as char);
            i += 1;
        }
    }

    let tokens = match tokenize_substituted(&substituted) {
        Some(t) if !t.is_empty() => t,
        _ => return EvalOutcome::SyntaxError,
    };

    let mut parser = ExprParser {
        tokens: &tokens,
        pos: 0,
    };
    match parser.parse_or() {
        Some(v) if parser.pos == parser.tokens.len() => EvalOutcome::Value(v),
        _ => EvalOutcome::SyntaxError,
    }
}

#[inline]
fn is_beckhoff_ident_start(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b'_' || b == b'|'
}

#[inline]
fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Num(i64),
    LParen,
    RParen,
    Not,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

fn tokenize_substituted(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            b'-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            b'*' => {
                out.push(Tok::Star);
                i += 1;
            }
            b'/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            b'%' => {
                out.push(Tok::Percent);
                i += 1;
            }
            b'!' => {
                if i + 1 < b.len() && b[i + 1] == b'=' {
                    out.push(Tok::Ne);
                    i += 2;
                } else {
                    out.push(Tok::Not);
                    i += 1;
                }
            }
            b'=' => {
                if i + 1 < b.len() && b[i + 1] == b'=' {
                    out.push(Tok::Eq);
                    i += 2;
                } else {
                    out.push(Tok::Eq);
                    i += 1;
                }
            }
            b'<' => {
                if i + 1 < b.len() && b[i + 1] == b'=' {
                    out.push(Tok::Le);
                    i += 2;
                } else if i + 1 < b.len() && b[i + 1] == b'>' {
                    out.push(Tok::Ne);
                    i += 2;
                } else {
                    out.push(Tok::Lt);
                    i += 1;
                }
            }
            b'>' => {
                if i + 1 < b.len() && b[i + 1] == b'=' {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    out.push(Tok::Gt);
                    i += 1;
                }
            }
            b'&' if i + 1 < b.len() && b[i + 1] == b'&' => {
                out.push(Tok::And);
                i += 2;
            }
            b'|' if i + 1 < b.len() && b[i + 1] == b'|' => {
                out.push(Tok::Or);
                i += 2;
            }
            c if c.is_ascii_digit() => {
                if c == b'0' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
                    let start = i + 2;
                    let mut end = start;
                    while end < b.len() && b[end].is_ascii_hexdigit() {
                        end += 1;
                    }
                    if end == start {
                        return None;
                    }
                    let v = i64::from_str_radix(&s[start..end], 16).ok()?;
                    out.push(Tok::Num(v));
                    i = end;
                } else {
                    let start = i;
                    let mut end = i + 1;
                    while end < b.len() && b[end].is_ascii_digit() {
                        end += 1;
                    }
                    // Reject trailing identifier chars like `0abc`
                    if end < b.len() && b[end].is_ascii_alphabetic() {
                        return None;
                    }
                    let v = s[start..end].parse::<i64>().ok()?;
                    out.push(Tok::Num(v));
                    i = end;
                }
            }
            _ => {
                // Any leftover lowercase word (e.g. `ifdef`, `defined`, single-char macro)
                // causes DataTable.Compute to throw -> SyntaxError -> SrcCodeType::Unexpected
                return None;
            }
        }
    }
    Some(out)
}

struct ExprParser<'a> {
    tokens: &'a [Tok],
    pos: usize,
}

impl<'a> ExprParser<'a> {
    fn peek(&self) -> Option<Tok> {
        self.tokens.get(self.pos).copied()
    }

    fn parse_or(&mut self) -> Option<i64> {
        let mut lhs = self.parse_and()?;
        while self.peek() == Some(Tok::Or) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = i64::from(lhs != 0 || rhs != 0);
        }
        Some(lhs)
    }

    fn parse_and(&mut self) -> Option<i64> {
        let mut lhs = self.parse_equality()?;
        while self.peek() == Some(Tok::And) {
            self.pos += 1;
            let rhs = self.parse_equality()?;
            lhs = i64::from(lhs != 0 && rhs != 0);
        }
        Some(lhs)
    }

    fn parse_equality(&mut self) -> Option<i64> {
        let mut lhs = self.parse_relational()?;
        loop {
            match self.peek() {
                Some(Tok::Eq) => {
                    self.pos += 1;
                    let rhs = self.parse_relational()?;
                    lhs = i64::from(lhs == rhs);
                }
                Some(Tok::Ne) => {
                    self.pos += 1;
                    let rhs = self.parse_relational()?;
                    lhs = i64::from(lhs != rhs);
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_relational(&mut self) -> Option<i64> {
        let mut lhs = self.parse_additive()?;
        loop {
            match self.peek() {
                Some(Tok::Lt) => {
                    self.pos += 1;
                    let rhs = self.parse_additive()?;
                    lhs = i64::from(lhs < rhs);
                }
                Some(Tok::Le) => {
                    self.pos += 1;
                    let rhs = self.parse_additive()?;
                    lhs = i64::from(lhs <= rhs);
                }
                Some(Tok::Gt) => {
                    self.pos += 1;
                    let rhs = self.parse_additive()?;
                    lhs = i64::from(lhs > rhs);
                }
                Some(Tok::Ge) => {
                    self.pos += 1;
                    let rhs = self.parse_additive()?;
                    lhs = i64::from(lhs >= rhs);
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_additive(&mut self) -> Option<i64> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Some(Tok::Plus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative()?;
                    lhs = lhs.wrapping_add(rhs);
                }
                Some(Tok::Minus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative()?;
                    lhs = lhs.wrapping_sub(rhs);
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_multiplicative(&mut self) -> Option<i64> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Tok::Star) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = lhs.wrapping_mul(rhs);
                }
                Some(Tok::Slash) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return None;
                    }
                    lhs = lhs.wrapping_div(rhs);
                }
                Some(Tok::Percent) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return None;
                    }
                    lhs = lhs.wrapping_rem(rhs);
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_unary(&mut self) -> Option<i64> {
        match self.peek()? {
            Tok::Not => {
                self.pos += 1;
                let v = self.parse_unary()?;
                Some(i64::from(v == 0))
            }
            Tok::Plus => {
                self.pos += 1;
                self.parse_unary()
            }
            Tok::Minus => {
                self.pos += 1;
                let v = self.parse_unary()?;
                Some(v.wrapping_neg())
            }
            Tok::LParen => {
                self.pos += 1;
                let v = self.parse_or()?;
                if self.peek() != Some(Tok::RParen) {
                    return None;
                }
                self.pos += 1;
                Some(v)
            }
            Tok::Num(n) => {
                self.pos += 1;
                Some(n)
            }
            _ => None,
        }
    }
}
