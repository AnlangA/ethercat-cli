use std::path::Path;

use ethercat_wire::error::{CliError, Result};

/// Lightweight DOM element tailored for ETG.2000 `<EtherCATInfo>` XML documents.
#[derive(Debug, Clone)]
pub struct XmlElement {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<XmlElement>,
}

impl XmlElement {
    pub fn attr(&self, target: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == target)
            .or_else(|| {
                self.attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(target))
            })
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&XmlElement> {
        self.children.iter().find(|c| c.name == name).or_else(|| {
            self.children
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(name))
        })
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlElement> {
        self.children
            .iter()
            .filter(move |c| c.name.eq_ignore_ascii_case(name))
    }

    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim())
    }
}

const CP1252_80_9F: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

pub(crate) fn decode_cp1252_latin1(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if (0x80..=0x9F).contains(&b) {
            out.push(CP1252_80_9F[(b - 0x80) as usize]);
        } else {
            out.push(char::from(b));
        }
    }
    out
}

/// Encode a Rust UTF-8 string into single-byte ETG.2010 `VISIBLESTRING` (`Windows-1252` /
/// `ISO-8859-1`) bytes, truncated to the 255-byte SII string limit (`?` fallback for unmapped codepoints).
pub(crate) fn encode_cp1252_latin1_trunc255(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len().min(255));
    for ch in s.chars() {
        if out.len() >= 255 {
            break;
        }
        let code = ch as u32;
        let b = if code <= 0x7F || (0xA0..=0xFF).contains(&code) {
            code as u8
        } else if let Some(idx) = CP1252_80_9F.iter().position(|&c| c == ch) {
            (0x80 + idx) as u8
        } else if (0x80..=0x9F).contains(&code) {
            code as u8
        } else {
            b'?'
        };
        out.push(b);
    }
    out
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
    if (bytes.len() & 1) != 0 {
        return Err(CliError::Format(
            "UTF-16 XML input has odd byte length".into(),
        ));
    }
    let units = bytes.as_chunks::<2>().0.iter().map(|&pair| {
        if little_endian {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        }
    });
    let mut out = String::with_capacity(bytes.len() / 2);
    for ch in char::decode_utf16(units) {
        let c = ch.map_err(|e| CliError::Format(format!("invalid UTF-16 XML sequence: {e}")))?;
        out.push(c);
    }
    Ok(out)
}

fn detect_bomless_utf16_endian(raw: &[u8]) -> Option<bool> {
    if raw.len() < 4 || (raw.len() & 1) != 0 {
        return None;
    }
    for &pair in raw[..raw.len().min(64)].as_chunks::<2>().0 {
        match pair {
            [b, 0x00] if b.is_ascii_whitespace() => continue,
            [0x00, b] if b.is_ascii_whitespace() => continue,
            [b'<', 0x00] => return Some(true),
            [0x00, b'<'] => return Some(false),
            _ => return None,
        }
    }
    None
}

fn detect_prolog_encoding(raw: &[u8]) -> Option<String> {
    let head_len = raw.len().min(256);
    let head_ascii: String = raw[..head_len]
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { ' ' })
        .collect();
    let trimmed = head_ascii.trim_start();
    if !trimmed.starts_with("<?xml") {
        return None;
    }
    let end = trimmed.find("?>")?;
    let prolog = &trimmed[..end];
    let lower = prolog.to_ascii_lowercase();
    let enc_pos = lower.find("encoding")?;
    let after_enc = prolog[enc_pos + "encoding".len()..].trim_start();
    let after_eq = after_enc.strip_prefix('=')?.trim_start();
    let quote = after_eq.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &after_eq[quote.len_utf8()..];
    let close = rest.find(quote)?;
    Some(rest[..close].trim().to_ascii_lowercase())
}

/// Decode owned XML bytes, reusing the `Vec<u8>` buffer directly in the common UTF-8 case
/// to cut peak memory consumption in half on multi-megabyte ESI XML files.
pub fn decode_xml_vec(raw: Vec<u8>) -> Result<String> {
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return match String::from_utf8(raw) {
            Ok(mut s) => {
                s.drain(..3);
                Ok(s)
            }
            Err(e) => Err(CliError::Format(format!(
                "invalid UTF-8 XML with BOM: {}",
                e.utf8_error()
            ))),
        };
    }
    if let Some(rest) = raw.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, true);
    }
    if let Some(rest) = raw.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, false);
    }
    if let Some(le) = detect_bomless_utf16_endian(&raw) {
        return decode_utf16(&raw, le);
    }
    if let Some(enc) = detect_prolog_encoding(&raw) {
        match enc.as_str() {
            "iso-8859-1" | "iso_8859-1" | "iso8859-1" | "latin1" | "latin-1" | "windows-1252"
            | "cp1252" | "us-ascii" | "ascii" => {
                return Ok(decode_cp1252_latin1(&raw));
            }
            "utf-16" | "utf-16le" => return decode_utf16(&raw, true),
            "utf-16be" => return decode_utf16(&raw, false),
            _ => {}
        }
    }
    match String::from_utf8(raw) {
        Ok(s) => Ok(s),
        Err(err) => Ok(decode_cp1252_latin1(&err.into_bytes())),
    }
}

/// Decode raw XML bytes supporting `UTF-8` (with/without BOM), `UTF-16LE`, `UTF-16BE`,
/// and `ISO-8859-1` / `Windows-1252` prolog declarations.
pub fn decode_xml_bytes(raw: &[u8]) -> Result<String> {
    if let Some(rest) = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(rest)
            .map(|s| s.to_string())
            .map_err(|e| CliError::Format(format!("invalid UTF-8 XML with BOM: {e}")));
    }
    if let Some(rest) = raw.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, true);
    }
    if let Some(rest) = raw.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, false);
    }
    if let Some(le) = detect_bomless_utf16_endian(raw) {
        return decode_utf16(raw, le);
    }

    if let Some(enc) = detect_prolog_encoding(raw) {
        match enc.as_str() {
            "iso-8859-1" | "iso_8859-1" | "iso8859-1" | "latin1" | "latin-1" | "windows-1252"
            | "cp1252" | "us-ascii" | "ascii" => {
                return Ok(decode_cp1252_latin1(raw));
            }
            "utf-16" | "utf-16le" => return decode_utf16(raw, true),
            "utf-16be" => return decode_utf16(raw, false),
            _ => {}
        }
    }

    match std::str::from_utf8(raw) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Ok(decode_cp1252_latin1(raw)),
    }
}

pub fn unescape_xml_cow(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.contains('&') {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let entity = &after[..semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if entity.starts_with('#') => {
                    entity[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

pub fn unescape_xml(input: &str) -> String {
    unescape_xml_cow(input).into_owned()
}

fn local_xml_name(raw_name: &str) -> &str {
    match raw_name.rsplit_once(':') {
        Some((_, local)) => local,
        None => raw_name,
    }
}

/// Elements inside multi-megabyte ESI files whose subtrees are never needed for SII EEPROM
/// compilation or device inspection (`<ImageData16x14>`, `<DiagMessages>`, `<Objects>`, `<SubItem>`).
fn should_skip_subtree(local_name: &str) -> bool {
    local_name.eq_ignore_ascii_case("ImageData16x14")
        || local_name.eq_ignore_ascii_case("DiagMessages")
        || local_name.eq_ignore_ascii_case("Objects")
        || local_name.eq_ignore_ascii_case("SubItem")
}

struct XmlScanner<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> XmlScanner<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn starts_with(&self, pat: &str) -> bool {
        self.src[self.pos..].starts_with(pat)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn find_sub(&self, pat: &str) -> Option<usize> {
        self.src[self.pos..].find(pat).map(|off| self.pos + off)
    }

    fn skip_comment(&mut self) -> Result<()> {
        let end = self
            .find_sub("-->")
            .ok_or_else(|| CliError::Format("unterminated XML comment '<!--'".into()))?;
        self.pos = end + 3;
        Ok(())
    }

    fn skip_pi(&mut self) -> Result<()> {
        let end = self.find_sub("?>").ok_or_else(|| {
            CliError::Format("unterminated XML processing instruction '<?'".into())
        })?;
        self.pos = end + 2;
        Ok(())
    }

    fn skip_doctype_or_decl(&mut self) -> Result<()> {
        // Starts at `<!` (not `<!--` and not `<![CDATA[`)
        self.pos += 2;
        let mut bracket_depth = 0usize;
        let mut quote: Option<u8> = None;
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
                continue;
            }
            match b {
                b'"' | b'\'' => quote = Some(b),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'>' if bracket_depth == 0 => return Ok(()),
                _ => {}
            }
        }
        Err(CliError::Format(
            "unterminated XML declaration '<!...>'".into(),
        ))
    }

    fn read_cdata(&mut self) -> Result<&'a str> {
        // Assumes starts_with("<![CDATA[")
        self.pos += 9;
        let start = self.pos;
        let end = self
            .find_sub("]]>")
            .ok_or_else(|| CliError::Format("unterminated XML '<![CDATA[' section".into()))?;
        self.pos = end + 3;
        Ok(&self.src[start..end])
    }

    fn read_name(&mut self) -> Result<&'a str> {
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_whitespace() || matches!(b, b'>' | b'/' | b'=' | b'<') {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(CliError::Format(format!(
                "expected XML name near byte offset {}",
                self.pos
            )));
        }
        Ok(&self.src[start..self.pos])
    }

    /// Fast zero-allocation skip of an open element's body up to its matching closing tag.
    fn skip_open_element_body(&mut self) -> Result<()> {
        let mut depth = 1usize;
        while depth > 0 {
            let rel = self.src[self.pos..].find('<').ok_or_else(|| {
                CliError::Format("unexpected EOF while skipping XML element".into())
            })?;
            self.pos += rel;
            if self.starts_with("<!--") {
                self.skip_comment()?;
            } else if self.starts_with("<![CDATA[") {
                let _ = self.read_cdata()?;
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("</") {
                self.pos += 2;
                let _ = self.read_name()?;
                self.skip_ws();
                if self.pos >= self.bytes.len() || self.bytes[self.pos] != b'>' {
                    return Err(CliError::Format("malformed closing tag in XML".into()));
                }
                self.pos += 1;
                depth -= 1;
            } else if self.starts_with("<!") {
                self.skip_doctype_or_decl()?;
            } else {
                // Opening or self-closing nested tag: scan to matching `>` outside quotes
                self.pos += 1;
                let mut quote: Option<u8> = None;
                let mut prev_non_ws = 0u8;
                let mut closed = false;
                while self.pos < self.bytes.len() {
                    let b = self.bytes[self.pos];
                    self.pos += 1;
                    if let Some(q) = quote {
                        if b == q {
                            quote = None;
                        }
                        continue;
                    }
                    if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b'>' {
                        closed = true;
                        if prev_non_ws != b'/' {
                            depth += 1;
                        }
                        break;
                    } else if !b.is_ascii_whitespace() {
                        prev_non_ws = b;
                    }
                }
                if !closed {
                    return Err(CliError::Format(
                        "unterminated nested XML tag while skipping subtree".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn parse_element(&mut self, depth: usize) -> Result<Option<XmlElement>> {
        const MAX_XML_DEPTH: usize = 128;
        if depth > MAX_XML_DEPTH {
            return Err(CliError::Format(format!(
                "XML element nesting exceeds maximum supported depth ({MAX_XML_DEPTH})"
            )));
        }
        // Assumes `self.bytes[self.pos] == b'<'` and not `</`, `<!--`, `<?`, `<!`
        self.pos += 1;
        let raw_tag = self.read_name()?;
        let local_name = local_xml_name(raw_tag);

        if should_skip_subtree(local_name) {
            // Scan attributes to see if self-closing `/>` or open `>`
            let mut quote: Option<u8> = None;
            let mut prev_non_ws = 0u8;
            let mut self_closing = false;
            let mut found_gt = false;
            while self.pos < self.bytes.len() {
                let b = self.bytes[self.pos];
                self.pos += 1;
                if let Some(q) = quote {
                    if b == q {
                        quote = None;
                    }
                    continue;
                }
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'>' {
                    found_gt = true;
                    self_closing = prev_non_ws == b'/';
                    break;
                } else if !b.is_ascii_whitespace() {
                    prev_non_ws = b;
                }
            }
            if !found_gt {
                return Err(CliError::Format(format!(
                    "unterminated XML start tag '<{raw_tag}'"
                )));
            }
            if !self_closing {
                self.skip_open_element_body()?;
            }
            return Ok(None);
        }

        let mut attrs = Vec::new();
        let self_closing;
        loop {
            self.skip_ws();
            if self.eof() {
                return Err(CliError::Format(format!(
                    "unexpected EOF inside start tag '<{raw_tag}'"
                )));
            }
            if self.starts_with("/>") {
                self.pos += 2;
                self_closing = true;
                break;
            }
            if self.bytes[self.pos] == b'>' {
                self.pos += 1;
                self_closing = false;
                break;
            }
            let raw_attr_name = self.read_name()?;
            let attr_name = local_xml_name(raw_attr_name).to_string();
            self.skip_ws();
            if self.eof() || self.bytes[self.pos] != b'=' {
                return Err(CliError::Format(format!(
                    "expected '=' after XML attribute '{raw_attr_name}' in '<{raw_tag}>'"
                )));
            }
            self.pos += 1;
            self.skip_ws();
            if self.eof() {
                return Err(CliError::Format(format!(
                    "unexpected EOF in attribute '{raw_attr_name}' value"
                )));
            }
            let quote = self.bytes[self.pos];
            if quote != b'"' && quote != b'\'' {
                return Err(CliError::Format(format!(
                    "expected quoted value for XML attribute '{raw_attr_name}'"
                )));
            }
            self.pos += 1;
            let val_start = self.pos;
            let val_rel_end = self.src[val_start..].find(quote as char).ok_or_else(|| {
                CliError::Format(format!("unterminated attribute '{raw_attr_name}' value"))
            })?;
            let raw_val = &self.src[val_start..val_start + val_rel_end];
            self.pos = val_start + val_rel_end + 1;
            attrs.push((attr_name, unescape_xml(raw_val)));
        }

        let mut elem = XmlElement {
            name: local_name.to_string(),
            attrs,
            text: String::new(),
            children: Vec::new(),
        };

        if self_closing {
            return Ok(Some(elem));
        }

        loop {
            let text_start = self.pos;
            let lt_rel = self.src[self.pos..].find('<').ok_or_else(|| {
                CliError::Format(format!(
                    "unexpected EOF waiting for closing tag '</{raw_tag}>'"
                ))
            })?;
            if lt_rel > 0 {
                let raw_text = &self.src[text_start..text_start + lt_rel];
                let next_src = &self.src[text_start + lt_rel..];
                let is_container_indent = elem.text.is_empty()
                    && raw_text.bytes().all(|b| b.is_ascii_whitespace())
                    && (!elem.children.is_empty()
                        || (!next_src.starts_with("</") && !next_src.starts_with("<![CDATA[")));
                if !raw_text.is_empty() && !is_container_indent {
                    elem.text.push_str(&unescape_xml_cow(raw_text));
                }
            }
            self.pos += lt_rel;

            if self.starts_with("<!--") {
                self.skip_comment()?;
            } else if self.starts_with("<![CDATA[") {
                let cdata = self.read_cdata()?;
                elem.text.push_str(cdata);
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("</") {
                self.pos += 2;
                let close_raw = self.read_name()?;
                let close_local = local_xml_name(close_raw);
                if close_local != elem.name {
                    return Err(CliError::Format(format!(
                        "mismatched XML closing tag: expected '</{}>', found '</{close_raw}>'",
                        elem.name
                    )));
                }
                self.skip_ws();
                if self.eof() || self.bytes[self.pos] != b'>' {
                    return Err(CliError::Format(format!(
                        "expected '>' at end of '</{close_raw}>'"
                    )));
                }
                self.pos += 1;
                break;
            } else if self.starts_with("<!") {
                self.skip_doctype_or_decl()?;
            } else if let Some(child) = self.parse_element(depth + 1)? {
                elem.children.push(child);
            }
        }

        Ok(Some(elem))
    }

    fn parse_root(&mut self) -> Result<XmlElement> {
        loop {
            self.skip_ws();
            if self.eof() {
                return Err(CliError::Format("empty XML document".into()));
            }
            if self.bytes[self.pos] != b'<' {
                return Err(CliError::Format(
                    "expected '<' at start of XML document".into(),
                ));
            }
            if self.starts_with("<!--") {
                self.skip_comment()?;
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("<!") {
                self.skip_doctype_or_decl()?;
            } else {
                return self
                    .parse_element(0)?
                    .ok_or_else(|| CliError::Format("root XML element cannot be skipped".into()));
            }
        }
    }
}

pub fn parse_xml_str(xml: &str) -> Result<XmlElement> {
    let stripped = xml.strip_prefix('\u{FEFF}').unwrap_or(xml);
    let mut scanner = XmlScanner::new(stripped);
    scanner.parse_root()
}

pub fn parse_xml_bytes(raw: &[u8]) -> Result<XmlElement> {
    let decoded = decode_xml_bytes(raw)?;
    parse_xml_str(&decoded)
}

pub fn parse_xml_file(path: &Path) -> Result<XmlElement> {
    let raw = std::fs::read(path).map_err(|e| {
        CliError::Usage(format!(
            "cannot read ESI XML file '{}': {e}",
            path.display()
        ))
    })?;
    let decoded = decode_xml_vec(raw).map_err(|e| match e {
        CliError::Format(msg) => CliError::Format(format!("in '{}': {msg}", path.display())),
        other => other,
    })?;
    parse_xml_str(&decoded).map_err(|e| match e {
        CliError::Format(msg) => CliError::Format(format!("in '{}': {msg}", path.display())),
        other => other,
    })
}
