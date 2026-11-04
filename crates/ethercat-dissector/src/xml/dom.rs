use ethercat_wire::error::{CliError, Result};

#[derive(Debug, Clone)]
pub struct XmlNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, tag: &str) -> Option<&XmlNode> {
        self.children
            .iter()
            .find(|c| c.tag.eq_ignore_ascii_case(tag))
    }

    pub fn children_named<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children
            .iter()
            .filter(move |c| c.tag.eq_ignore_ascii_case(tag))
    }

    pub fn child_text<'a>(&'a self, tag: &str) -> Option<&'a str> {
        // Prefer English (`LcId="1033"`) or neutral when multiple localized `<Name>` elements exist
        let mut fallback = None;
        for c in &self.children {
            if !c.tag.eq_ignore_ascii_case(tag) {
                continue;
            }
            let txt = c.text.trim();
            if txt.is_empty() {
                continue;
            }
            if let Some(lc) = c.attr("LcId") {
                if lc.trim() == "1033" {
                    return Some(txt);
                }
            } else {
                return Some(txt);
            }
            if fallback.is_none() {
                fallback = Some(txt);
            }
        }
        fallback
    }
}

const WIN1252_80_9F: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

pub fn decode_xml_bytes(raw: &[u8]) -> Result<String> {
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(&raw[3..])
            .map(|s| s.to_string())
            .map_err(|e| CliError::Format(format!("invalid UTF-8 after BOM: {e}")));
    }
    if raw.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();
        return String::from_utf16(&units)
            .map_err(|e| CliError::Format(format!("invalid UTF-16LE XML: {e}")));
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .collect();
        return String::from_utf16(&units)
            .map_err(|e| CliError::Format(format!("invalid UTF-16BE XML: {e}")));
    }
    if raw.len() >= 4 && raw[0] == b'<' && raw[1] == 0 {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();
        return String::from_utf16(&units)
            .map_err(|e| CliError::Format(format!("invalid UTF-16LE XML: {e}")));
    }
    if raw.len() >= 4 && raw[0] == 0 && raw[1] == b'<' {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .collect();
        return String::from_utf16(&units)
            .map_err(|e| CliError::Format(format!("invalid UTF-16BE XML: {e}")));
    }
    if let Ok(s) = std::str::from_utf8(raw) {
        return Ok(s.to_string());
    }
    // ISO-8859-1 / Windows-1252 fallback (common in European ESI files with `µ`, `°`, `€`, `–`, umlauts)
    Ok(raw
        .iter()
        .map(|&b| {
            if (0x80..=0x9F).contains(&b) {
                WIN1252_80_9F[(b - 0x80) as usize]
            } else {
                b as char
            }
        })
        .collect())
}

pub fn unescape_xml(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let ent = &after[..semi];
            let decoded = match ent {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
            } else {
                out.push('&');
                out.push_str(ent);
                out.push(';');
            }
            rest = &after[semi + 1..];
        } else {
            out.push('&');
            out.push_str(after);
            break;
        }
    }
    out.push_str(rest);
    out
}

fn strip_ns(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

type TagHeader = (String, Vec<(String, String)>, bool);

fn parse_tag_header(inner: &str) -> Result<TagHeader> {
    let trimmed = inner.trim();
    let (body, self_closing) = if let Some(stripped) = trimmed.strip_suffix('/') {
        (stripped.trim_end(), true)
    } else {
        (trimmed, false)
    };
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == 0 {
        return Err(CliError::Format("empty XML element tag".into()));
    }
    let tag_name = strip_ns(&body[..i]).to_string();
    let mut attrs = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let k_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = strip_ns(&body[k_start..i]).to_string();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        if quote == b'"' || quote == b'\'' {
            i += 1;
            let v_start = i;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            let val = unescape_xml(&body[v_start..i]);
            if i < bytes.len() {
                i += 1;
            }
            attrs.push((key, val));
        } else {
            let v_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            attrs.push((key, unescape_xml(&body[v_start..i])));
        }
    }
    Ok((tag_name, attrs, self_closing))
}

fn find_tag_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_quote: Option<u8> = None;
    for (idx, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            in_quote = Some(b);
        } else if b == b'>' {
            return Some(idx);
        }
    }
    None
}

pub fn parse_xml_document(src: &str) -> Result<XmlNode> {
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;
    let mut pos = 0usize;
    let bytes = src.as_bytes();

    while pos < bytes.len() {
        if let Some(rel_lt) = src[pos..].find('<') {
            let lt = pos + rel_lt;
            if lt > pos {
                if let Some(top) = stack.last_mut() {
                    let txt = &src[pos..lt];
                    if !txt.trim().is_empty() || !top.text.is_empty() {
                        top.text.push_str(&unescape_xml(txt));
                    }
                }
            }
            let rest = &src[lt..];
            if rest.starts_with("<!--") {
                let end = rest
                    .find("-->")
                    .ok_or_else(|| CliError::Format("unclosed XML comment".into()))?;
                pos = lt + end + 3;
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                let end = rest
                    .find("]]>")
                    .ok_or_else(|| CliError::Format("unclosed CDATA section".into()))?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&rest[9..end]);
                }
                pos = lt + end + 3;
                continue;
            }
            if rest.starts_with("<?") {
                let end = rest.find("?>").ok_or_else(|| {
                    CliError::Format("unclosed XML processing instruction".into())
                })?;
                pos = lt + end + 2;
                continue;
            }
            if rest.starts_with("<!") {
                // Skip DOCTYPE or entity declarations (handling nested `[...]`)
                let mut depth = 0i32;
                let mut i = 2usize;
                let rb = rest.as_bytes();
                while i < rb.len() {
                    if rb[i] == b'[' {
                        depth += 1;
                    } else if rb[i] == b']' {
                        depth -= 1;
                    } else if rb[i] == b'>' && depth <= 0 {
                        break;
                    }
                    i += 1;
                }
                pos = (lt + i + 1).min(bytes.len());
                continue;
            }
            let gt = find_tag_end(&rest[1..])
                .ok_or_else(|| CliError::Format("unclosed XML tag '>'".into()))?
                + 1;
            let inner = &rest[1..gt];
            pos = lt + gt + 1;

            if let Some(close_raw) = inner.strip_prefix('/') {
                let close_tag = strip_ns(close_raw.trim());
                let finished = stack.pop().ok_or_else(|| {
                    CliError::Format(format!("unexpected closing tag </{close_tag}>"))
                })?;
                if !finished.tag.eq_ignore_ascii_case(close_tag) {
                    return Err(CliError::Format(format!(
                        "mismatched XML tag: opened <{}>, closed </{close_tag}>",
                        finished.tag
                    )));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(finished);
                } else {
                    root = Some(finished);
                    break;
                }
            } else {
                let (tag, attrs, self_closing) = parse_tag_header(inner)?;
                let node = XmlNode {
                    tag,
                    attrs,
                    text: String::new(),
                    children: Vec::new(),
                };
                if self_closing {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        root = Some(node);
                        break;
                    }
                } else {
                    stack.push(node);
                }
            }
        } else {
            break;
        }
    }

    root.ok_or_else(|| CliError::Format("empty or unclosed XML document".into()))
}
