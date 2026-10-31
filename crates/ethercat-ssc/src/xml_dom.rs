use std::path::Path;

use ethercat_eeprom::esi::xml::{decode_xml_bytes, decode_xml_vec, unescape_xml};
use ethercat_wire::error::{CliError, Result};

/// Full-fidelity XML child node preserving elements, text, comments, and CDATA in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomNode {
    Element(DomElement),
    Text(String),
    Comment(String),
    CData(String),
}

impl From<DomElement> for DomNode {
    fn from(el: DomElement) -> Self {
        Self::Element(el)
    }
}

/// Full-fidelity XML element (preserving prefixes/attributes/children without ESI tag skipping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomElement {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<DomNode>,
}

impl DomElement {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn with_text(name: impl Into<String>, text: impl Into<String>) -> Self {
        let mut el = Self::new(name);
        let s = text.into();
        if !s.is_empty() {
            el.children.push(DomNode::Text(s));
        }
        el
    }

    pub fn set_attr(&mut self, key: impl Into<String>, val: impl Into<String>) {
        let k = key.into();
        let v = val.into();
        if let Some((_, existing)) = self.attrs.iter_mut().find(|(ak, _)| ak == &k) {
            *existing = v;
        } else {
            self.attrs.push((k, v));
        }
    }

    pub fn push_attr(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.attrs.push((key.into(), val.into()));
    }

    pub fn attr(&self, target: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == target)
            .or_else(|| {
                self.attrs
                    .iter()
                    .find(|(k, _)| local_name(k) == target || k.eq_ignore_ascii_case(target))
            })
            .map(|(_, v)| v.as_str())
    }

    pub fn local_name(&self) -> &str {
        local_name(&self.name)
    }

    pub fn push_child(&mut self, child: impl Into<DomNode>) {
        self.children.push(child.into());
    }

    pub fn push_text(&mut self, text: impl Into<String>) {
        let s = text.into();
        if !s.is_empty() {
            self.children.push(DomNode::Text(s));
        }
    }

    pub fn push_comment(&mut self, comment: impl Into<String>) {
        self.children.push(DomNode::Comment(comment.into()));
    }

    pub fn child_elements(&self) -> impl Iterator<Item = &DomElement> {
        self.children.iter().filter_map(|n| match n {
            DomNode::Element(e) => Some(e),
            _ => None,
        })
    }

    pub fn child(&self, name: &str) -> Option<&DomElement> {
        self.child_elements()
            .find(|c| c.name == name || c.local_name() == name)
            .or_else(|| {
                self.child_elements()
                    .find(|c| c.local_name().eq_ignore_ascii_case(name))
            })
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut DomElement> {
        let exact_idx = self
            .children
            .iter()
            .position(
                |n| matches!(n, DomNode::Element(c) if c.name == name || c.local_name() == name),
            )
            .or_else(|| {
                self.children.iter().position(|n| {
                    matches!(n, DomNode::Element(c) if c.local_name().eq_ignore_ascii_case(name))
                })
            })?;
        match &mut self.children[exact_idx] {
            DomNode::Element(c) => Some(c),
            _ => None,
        }
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a DomElement> {
        self.child_elements()
            .filter(move |c| c.name == name || c.local_name().eq_ignore_ascii_case(name))
    }

    /// Concatenated direct text/CDATA children (comparable to `XmlNode.InnerText` when leaf,
    /// or concatenating `XmlNodeType.Text` children).
    pub fn direct_text(&self) -> String {
        let mut out = String::new();
        for n in &self.children {
            match n {
                DomNode::Text(t) | DomNode::CData(t) => out.push_str(t),
                _ => {}
            }
        }
        out
    }

    /// Recursive `InnerText` across all descendant text/CDATA nodes.
    pub fn inner_text(&self) -> String {
        let mut out = String::new();
        self.collect_inner_text(&mut out);
        out
    }

    pub fn text_content(&self) -> String {
        self.inner_text()
    }

    fn collect_inner_text(&self, out: &mut String) {
        for n in &self.children {
            match n {
                DomNode::Text(t) | DomNode::CData(t) => out.push_str(t),
                DomNode::Element(e) => e.collect_inner_text(out),
                DomNode::Comment(_) => {}
            }
        }
    }

    pub fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.inner_text())
    }
}

pub fn local_name(raw: &str) -> &str {
    match raw.rsplit_once(':') {
        Some((_, local)) => local,
        None => raw,
    }
}

/// Legacy semicolon-less entity unescaper matching `ConfigXmlDoc::GetClearValue(String)`.
pub fn get_clear_value(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    input
        .replace("&amp", "&")
        .replace("&apos", "'")
        .replace("&lt", "<")
        .replace("&gt", ">")
        .replace("&quot", "\"")
}

/// Stream-escape an XML attribute value directly into `out` matching `.NET XmlWriter`
/// (`&`, `<`, `>`, `"`, `\r`, `\n`, `\t`), avoiding intermediate `String` allocation.
pub fn push_escaped_xml_attr(out: &mut String, val: &str) {
    if !val
        .bytes()
        .any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\r' | b'\n' | b'\t'))
    {
        out.push_str(val);
        return;
    }
    for ch in val.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#xD;"),
            '\n' => out.push_str("&#xA;"),
            '\t' => out.push_str("&#x9;"),
            _ => out.push(ch),
        }
    }
}

/// Stream-escape XML element text directly into `out` matching `.NET XmlWriter` (`&`, `<`, `>`),
/// avoiding intermediate `String` allocation.
pub fn push_escaped_xml_text(out: &mut String, val: &str) {
    if !val.bytes().any(|b| matches!(b, b'&' | b'<' | b'>')) {
        out.push_str(val);
        return;
    }
    for ch in val.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
}

/// Parse an XML file into a `DomElement` (`preserve_whitespace = false` matches `.NET XmlDocument` default).
pub fn parse_dom_file(path: &Path, preserve_whitespace: bool) -> Result<DomElement> {
    let raw = std::fs::read(path).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read XML file '{}': {e}", path.display()),
        ))
    })?;
    let decoded = decode_xml_vec(raw).map_err(|e| match e {
        CliError::Format(msg) => CliError::Format(format!("in '{}': {msg}", path.display())),
        other => other,
    })?;
    parse_dom_str(&decoded, preserve_whitespace).map_err(|e| match e {
        CliError::Format(msg) => CliError::Format(format!("in '{}': {msg}", path.display())),
        other => other,
    })
}

/// Parse raw XML bytes into a `DomElement`.
pub fn parse_dom_bytes(raw: &[u8], preserve_whitespace: bool) -> Result<DomElement> {
    let decoded = decode_xml_bytes(raw)?;
    parse_dom_str(&decoded, preserve_whitespace)
}

/// Parse an XML string into a `DomElement`.
pub fn parse_dom_str(xml: &str, preserve_whitespace: bool) -> Result<DomElement> {
    let stripped = xml.strip_prefix('\u{FEFF}').unwrap_or(xml);
    let mut scanner = DomScanner {
        src: stripped,
        bytes: stripped.as_bytes(),
        pos: 0,
        preserve_whitespace,
    };
    scanner.parse_root()
}

struct DomScanner<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    preserve_whitespace: bool,
}

impl<'a> DomScanner<'a> {
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

    fn read_comment(&mut self) -> Result<String> {
        // Starts at `<!--`
        self.pos += 4;
        let start = self.pos;
        let end = self
            .find_sub("-->")
            .ok_or_else(|| CliError::Format("unterminated XML comment '<!--'".into()))?;
        self.pos = end + 3;
        Ok(self.src[start..end].to_string())
    }

    fn skip_pi(&mut self) -> Result<()> {
        let end = self.find_sub("?>").ok_or_else(|| {
            CliError::Format("unterminated XML processing instruction '<?'".into())
        })?;
        self.pos = end + 2;
        Ok(())
    }

    fn skip_doctype_or_decl(&mut self) -> Result<()> {
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

    fn read_cdata(&mut self) -> Result<String> {
        self.pos += 9;
        let start = self.pos;
        let end = self
            .find_sub("]]>")
            .ok_or_else(|| CliError::Format("unterminated XML '<![CDATA[' section".into()))?;
        self.pos = end + 3;
        Ok(self.src[start..end].to_string())
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

    fn parse_element(&mut self, depth: usize) -> Result<DomElement> {
        const MAX_DEPTH: usize = 160;
        if depth > MAX_DEPTH {
            return Err(CliError::Format(format!(
                "XML nesting exceeds maximum depth ({MAX_DEPTH})"
            )));
        }
        self.pos += 1;
        let raw_tag = self.read_name()?.to_string();

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
            let attr_name = self.read_name()?.to_string();
            self.skip_ws();
            if self.eof() || self.bytes[self.pos] != b'=' {
                return Err(CliError::Format(format!(
                    "expected '=' after XML attribute '{attr_name}' in '<{raw_tag}>'"
                )));
            }
            self.pos += 1;
            self.skip_ws();
            if self.eof() {
                return Err(CliError::Format(format!(
                    "unexpected EOF in attribute '{attr_name}' value"
                )));
            }
            let quote = self.bytes[self.pos];
            if quote != b'"' && quote != b'\'' {
                return Err(CliError::Format(format!(
                    "expected quoted value for XML attribute '{attr_name}'"
                )));
            }
            self.pos += 1;
            let val_start = self.pos;
            let val_rel_end = self.src[val_start..].find(quote as char).ok_or_else(|| {
                CliError::Format(format!("unterminated attribute '{attr_name}' value"))
            })?;
            let raw_val = &self.src[val_start..val_start + val_rel_end];
            self.pos = val_start + val_rel_end + 1;
            attrs.push((attr_name, unescape_xml(raw_val)));
        }

        let xml_space_preserve = attrs
            .iter()
            .any(|(k, v)| k == "xml:space" && v == "preserve");

        let mut elem = DomElement {
            name: raw_tag.clone(),
            attrs,
            children: Vec::new(),
        };

        if self_closing {
            return Ok(elem);
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
                if !raw_text.is_empty() {
                    elem.children.push(DomNode::Text(unescape_xml(raw_text)));
                }
            }
            self.pos += lt_rel;

            if self.starts_with("<!--") {
                let c = self.read_comment()?;
                elem.children.push(DomNode::Comment(c));
            } else if self.starts_with("<![CDATA[") {
                let cdata = self.read_cdata()?;
                elem.children.push(DomNode::CData(cdata));
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("</") {
                self.pos += 2;
                let close_raw = self.read_name()?;
                if close_raw != raw_tag && local_name(close_raw) != local_name(&raw_tag) {
                    return Err(CliError::Format(format!(
                        "mismatched XML closing tag: expected '</{raw_tag}>', found '</{close_raw}>'"
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
            } else {
                let child = self.parse_element(depth + 1)?;
                elem.children.push(DomNode::Element(child));
            }
        }

        // Match `.NET XmlDocument` (`PreserveWhitespace = false`):
        // When an element contains child elements/comments (or pure formatting whitespace),
        // pure-whitespace `Text` nodes (`[\r\n\t ]+`) are discarded unless `xml:space="preserve"`.
        if !self.preserve_whitespace && !xml_space_preserve {
            let has_non_text = elem
                .children
                .iter()
                .any(|n| matches!(n, DomNode::Element(_) | DomNode::Comment(_)));
            if has_non_text {
                elem.children.retain(|n| match n {
                    DomNode::Text(s) => !is_xml_whitespace_only(s),
                    _ => true,
                });
            } else if elem.children.len() == 1 {
                if let DomNode::Text(s) = &elem.children[0] {
                    if is_xml_whitespace_only(s) {
                        elem.children.clear();
                    }
                }
            }
        }

        Ok(elem)
    }

    fn parse_root(&mut self) -> Result<DomElement> {
        let mut leading_comments: Vec<String> = Vec::new();
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
                leading_comments.push(self.read_comment()?);
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("<!") {
                self.skip_doctype_or_decl()?;
            } else {
                return self.parse_element(0);
            }
        }
    }
}

#[inline]
fn is_xml_whitespace_only(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
}

/// Render single-line compact XML matching `.NET XmlDocument.InnerXml` (used for `.esp` / `.escfg`!).
pub fn render_compact_xml(root: &DomElement, xml_prolog: Option<&str>) -> String {
    let mut out = String::with_capacity(64 * 1024);
    if let Some(prolog) = xml_prolog {
        out.push_str(prolog);
    }
    write_element_compact(&mut out, root);
    out
}

fn write_element_compact(out: &mut String, el: &DomElement) {
    out.push('<');
    out.push_str(&el.name);
    for (k, v) in &el.attrs {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        push_escaped_xml_attr(out, v);
        out.push('"');
    }
    if el.children.is_empty() {
        out.push_str(" />");
        return;
    }
    out.push('>');
    for node in &el.children {
        match node {
            DomNode::Element(child) => write_element_compact(out, child),
            DomNode::Text(t) => push_escaped_xml_text(out, t),
            DomNode::Comment(c) => {
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->");
            }
            DomNode::CData(cd) => {
                out.push_str("<![CDATA[");
                out.push_str(cd);
                out.push_str("]]>");
            }
        }
    }
    out.push_str("</");
    out.push_str(&el.name);
    out.push('>');
}

/// Render pretty-printed XML matching `.NET XmlDocument.Save(path)` / `XmlWriter`
/// (with `\r\n` newlines, configurable `indent_unit` such as `"\t"` or `"  "`, and `<Tag />` empty tags).
pub fn render_indented_xml_bytes(
    root: &DomElement,
    xml_prolog: Option<&str>,
    indent_unit: &str,
    utf8_bom: bool,
    full_end_tags: bool,
) -> Vec<u8> {
    let mut out = String::with_capacity(32 * 1024);
    if let Some(prolog) = xml_prolog {
        out.push_str(prolog);
        out.push_str("\r\n");
    }
    write_element_indented(&mut out, root, 0, indent_unit, full_end_tags);
    if utf8_bom {
        let mut bytes = Vec::with_capacity(3 + out.len());
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        bytes.extend_from_slice(out.as_bytes());
        bytes
    } else {
        out.into_bytes()
    }
}

fn write_indent(out: &mut String, depth: usize, indent_unit: &str) {
    for _ in 0..depth {
        out.push_str(indent_unit);
    }
}

fn write_element_indented(
    out: &mut String,
    el: &DomElement,
    depth: usize,
    indent_unit: &str,
    full_end_tags: bool,
) {
    write_indent(out, depth, indent_unit);
    out.push('<');
    out.push_str(&el.name);
    for (k, v) in &el.attrs {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        push_escaped_xml_attr(out, v);
        out.push('"');
    }

    if el.children.is_empty() {
        if full_end_tags {
            out.push_str("></");
            out.push_str(&el.name);
            out.push('>');
        } else {
            out.push_str(" />");
        }
        return;
    }

    // Single-pass child classification
    let mut has_element = false;
    let mut has_comment = false;
    let mut has_text = false;
    for n in &el.children {
        match n {
            DomNode::Element(_) => has_element = true,
            DomNode::Comment(_) => has_comment = true,
            DomNode::Text(_) => has_text = true,
            DomNode::CData(_) => {}
        }
    }
    let only_inline_text = !has_element && !has_comment;
    let has_mixed_text_and_elements = has_text && has_element;

    if only_inline_text {
        out.push('>');
        for n in &el.children {
            match n {
                DomNode::Text(t) => push_escaped_xml_text(out, t),
                DomNode::CData(cd) => {
                    out.push_str("<![CDATA[");
                    out.push_str(cd);
                    out.push_str("]]>");
                }
                _ => {}
            }
        }
        out.push_str("</");
        out.push_str(&el.name);
        out.push('>');
        return;
    }

    if has_mixed_text_and_elements {
        // Mixed content (e.g. `<Setting>` with `<Flags />Description text`):
        // render children without injecting corrupting whitespace inside text!
        out.push('>');
        for n in &el.children {
            match n {
                DomNode::Element(child) => write_element_compact(out, child),
                DomNode::Text(t) => push_escaped_xml_text(out, t),
                DomNode::Comment(c) => {
                    out.push_str("<!--");
                    out.push_str(c);
                    out.push_str("-->");
                }
                DomNode::CData(cd) => {
                    out.push_str("<![CDATA[");
                    out.push_str(cd);
                    out.push_str("]]>");
                }
            }
        }
        out.push_str("</");
        out.push_str(&el.name);
        out.push('>');
        return;
    }

    out.push_str(">\r\n");
    for n in &el.children {
        match n {
            DomNode::Element(child) => {
                write_element_indented(out, child, depth + 1, indent_unit, full_end_tags);
                out.push_str("\r\n");
            }
            DomNode::Comment(c) => {
                write_indent(out, depth + 1, indent_unit);
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->\r\n");
            }
            DomNode::Text(t) => {
                push_escaped_xml_text(out, t);
            }
            DomNode::CData(cd) => {
                out.push_str("<![CDATA[");
                out.push_str(cd);
                out.push_str("]]>");
            }
        }
    }
    write_indent(out, depth, indent_unit);
    out.push_str("</");
    out.push_str(&el.name);
    out.push('>');
}
