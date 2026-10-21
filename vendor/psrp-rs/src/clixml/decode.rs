//! CLIXML decoder.
//!
//! Tolerant: unknown elements are skipped; a dangling `<Ref>` decodes to
//! [`PsValue::Null`]; leading whitespace / BOM / `<Objs>` wrappers are
//! accepted transparently.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::{PsObject, PsValue};
use crate::error::{PsrpError, Result};

/// Parse a CLIXML fragment into a sequence of top-level values.
///
/// A single CLIXML body may contain several siblings (a PSRP `PipelineOutput`
/// message, for example, is one `<Obj>` at the top level — but a
/// `SessionCapability` message consists of an `<Obj>` with a `<MS>` of
/// primitive siblings, which this parser also handles).
pub fn parse_clixml(xml: &str) -> Result<Vec<PsValue>> {
    let cleaned = xml.trim_start_matches('\u{FEFF}').trim_start();
    let mut reader = Reader::from_str(cleaned);
    reader.config_mut().trim_text(false);

    let mut state = DecoderState::default();
    let mut out: Vec<PsValue> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(value) = parse_element(&mut reader, &e, &mut state)? {
                    out.push(value);
                }
            }
            Event::Empty(e) => {
                if let Some(value) = parse_empty(&e, &mut state)? {
                    out.push(value);
                } else if e.name().as_ref() == "Ref" {
                    let rid = ref_ref_id_attr(&e)?;
                    out.push(
                        rid.and_then(|r| state.refs.get(&r).cloned())
                            .unwrap_or(PsValue::Null),
                    );
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(out)
}

/// Maximum `<Obj>` / `<LST>` / `<DCT>` nesting accepted from the wire.
///
/// The parser is recursive, and the document comes from the remote host:
/// without a cap, ~10 KiB of `<Obj><MS>` repeated is enough to overflow
/// the stack and **abort the process** — a stack overflow is not a
/// catchable panic, so `forbid(unsafe_code)` buys nothing here.
///
/// 64 was measured as the deepest level that still fits comfortably in
/// the 2 MiB stack of a Tokio worker thread in a debug build, and it is
/// an order of magnitude more than PowerShell's own serializer ever
/// emits (`Serialization.MaximumDepth` defaults to 1).
pub const MAX_NESTING_DEPTH: u32 = 64;

#[derive(Default)]
struct DecoderState {
    refs: HashMap<String, PsValue>,
    type_names: HashMap<String, Vec<String>>,
    /// Current nesting level, maintained by [`parse_element`].
    depth: u32,
}

/// Read the `N="…"` property-name attribute.
///
/// The value is XML-unescaped and then run through the PowerShell
/// `_xHHHH_` decoder, mirroring exactly what `encode::escape` did on the
/// way out. Skipping either step corrupts any property name containing
/// `&`, `<`, `>`, `"`, `'` or a control character — and because the
/// re-encoder escapes the result again, the damage compounds on every
/// hop (`&lt;` becomes `&amp;lt;` becomes `&amp;amp;lt;` …).
fn name_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == "N" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(decode_pwsh_escapes(&unescaped)));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of an `<Obj>` / `<TN>`.
fn ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == "RefId" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(unescaped.into_owned()));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of a `<Ref>` / `<TNRef>`.
fn ref_ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    ref_id_attr(e)
}

fn parse_empty(e: &BytesStart, _state: &mut DecoderState) -> Result<Option<PsValue>> {
    match e.name().as_ref() {
        "Nil" => Ok(Some(PsValue::Null)),
        "S" => Ok(Some(PsValue::String(String::new()))),
        "ToString" => Ok(None),
        _ => Ok(None),
    }
}

fn parse_int<T>(reader: &mut Reader<&[u8]>, closing: &str) -> Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    let text = read_text(reader, closing)?;
    text.trim()
        .parse::<T>()
        .map_err(|err| PsrpError::clixml(format!("{closing}: {err}")))
}

fn parse_float(s: &str) -> std::result::Result<f64, String> {
    match s {
        "NaN" => Ok(f64::NAN),
        "Infinity" => Ok(f64::INFINITY),
        "-Infinity" => Ok(f64::NEG_INFINITY),
        other => other.parse::<f64>().map_err(|e| e.to_string()),
    }
}

/// Depth-guarded entry point for element parsing.
///
/// Every recursion cycle in this module passes through here
/// (`parse_element` → `parse_obj_body` → `parse_member_set` /
/// `parse_list` / `parse_dict` → `parse_element`), so one counter is
/// enough to bound them all.
fn parse_element(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    if state.depth >= MAX_NESTING_DEPTH {
        return Err(PsrpError::clixml(format!(
            "CLIXML nested deeper than {MAX_NESTING_DEPTH} levels"
        )));
    }
    state.depth += 1;
    let result = parse_element_inner(reader, e, state);
    state.depth -= 1;
    result
}

fn parse_element_inner(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    let tag = e.name().as_ref().to_string();
    match tag.as_str() {
        "S" => {
            let text = read_text(reader, "S")?;
            Ok(Some(PsValue::String(text)))
        }
        "I32" => {
            let text = read_text(reader, "I32")?;
            let v = text
                .trim()
                .parse::<i32>()
                .map_err(|err| PsrpError::clixml(format!("I32: {err}")))?;
            Ok(Some(PsValue::I32(v)))
        }
        "I64" => {
            let text = read_text(reader, "I64")?;
            let v = text
                .trim()
                .parse::<i64>()
                .map_err(|err| PsrpError::clixml(format!("I64: {err}")))?;
            Ok(Some(PsValue::I64(v)))
        }
        "B" => {
            let text = read_text(reader, "B")?;
            let v = match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => return Err(PsrpError::clixml(format!("B: bad bool '{other}'"))),
            };
            Ok(Some(PsValue::Bool(v)))
        }
        "Db" => {
            let text = read_text(reader, "Db")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Db: {err}")))?;
            Ok(Some(PsValue::Double(v)))
        }
        "Sg" => {
            let text = read_text(reader, "Sg")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Sg: {err}")))?;
            Ok(Some(PsValue::F32(v as f32)))
        }
        "SB" => Ok(Some(PsValue::I8(parse_int(reader, "SB")?))),
        "By" => Ok(Some(PsValue::U8(parse_int(reader, "By")?))),
        "I16" => Ok(Some(PsValue::I16(parse_int(reader, "I16")?))),
        "U16" => Ok(Some(PsValue::U16(parse_int(reader, "U16")?))),
        "U32" => Ok(Some(PsValue::U32(parse_int(reader, "U32")?))),
        "U64" => Ok(Some(PsValue::U64(parse_int(reader, "U64")?))),
        "D" => {
            let text = read_text(reader, "D")?;
            Ok(Some(PsValue::Decimal(text.trim().to_string())))
        }
        "C" => {
            let text = read_text(reader, "C")?;
            let code: u32 = text
                .trim()
                .parse()
                .map_err(|err| PsrpError::clixml(format!("C: {err}")))?;
            let ch = char::from_u32(code)
                .ok_or_else(|| PsrpError::clixml(format!("C: invalid code point {code}")))?;
            Ok(Some(PsValue::Char(ch)))
        }
        "BA" => {
            let text = read_text(reader, "BA")?;
            let bytes = super::encode::base64_decode(text.trim())
                .ok_or_else(|| PsrpError::clixml("BA: invalid base64".to_string()))?;
            Ok(Some(PsValue::Bytes(bytes)))
        }
        "DT" => {
            let text = read_text(reader, "DT")?;
            Ok(Some(PsValue::DateTime(text)))
        }
        "TS" => {
            let text = read_text(reader, "TS")?;
            Ok(Some(PsValue::Duration(text)))
        }
        "G" => {
            let text = read_text(reader, "G")?;
            let uuid = uuid::Uuid::parse_str(text.trim())
                .map_err(|err| PsrpError::clixml(format!("G: {err}")))?;
            Ok(Some(PsValue::Guid(uuid)))
        }
        "Version" => {
            let text = read_text(reader, "Version")?;
            Ok(Some(PsValue::Version(text)))
        }
        "URI" => {
            let text = read_text(reader, "URI")?;
            Ok(Some(PsValue::Uri(text)))
        }
        "XD" => {
            let text = read_text(reader, "XD")?;
            Ok(Some(PsValue::Xml(text)))
        }
        "SCT" => {
            let text = read_text(reader, "SCT")?;
            Ok(Some(PsValue::ScriptBlock(text)))
        }
        "SS" => {
            let text = read_text(reader, "SS")?;
            Ok(Some(PsValue::SecureString(text)))
        }
        "Obj" => {
            let ref_id = ref_id_attr(e)?;
            let obj = parse_obj_body(reader, state)?;
            let value = PsValue::Object(obj.clone());
            if let Some(rid) = ref_id {
                state.refs.insert(rid, value.clone());
            }
            // Flatten: if the object has no properties and no type names
            // but its inline LST/DCT was captured elsewhere we still report
            // the object as-is. Otherwise the caller uses `properties()`.
            Ok(Some(value))
        }
        "Ref" => {
            let rid = ref_ref_id_attr(e)?;
            // self-closing `<Ref/>` handled by parse_empty; otherwise drain.
            skip_to_end(reader)?;
            Ok(Some(
                rid.and_then(|r| state.refs.get(&r).cloned())
                    .unwrap_or(PsValue::Null),
            ))
        }
        _ => {
            // Unknown top-level element — skip.
            skip_to_end(reader)?;
            Ok(None)
        }
    }
}

fn parse_obj_body(reader: &mut Reader<&[u8]>, state: &mut DecoderState) -> Result<PsObject> {
    let mut obj = PsObject::new();
    let mut buf = Vec::new();
    let mut embedded: Option<PsValue> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => match e.name().as_ref() {
                "MS" | "Props" => {
                    parse_member_set(reader, state, &mut obj, e.name().as_ref().to_string())?;
                }
                "TN" => {
                    let rid = ref_id_attr(&e)?;
                    let names = parse_type_names(reader)?;
                    if let Some(rid) = rid.clone() {
                        state.type_names.insert(rid, names.clone());
                    }
                    obj.type_names = names;
                }
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    skip_to_end(reader)?;
                    if let Some(rid) = rid
                        && let Some(names) = state.type_names.get(&rid)
                    {
                        obj.type_names.clone_from(names);
                    }
                }
                "LST" | "IE" | "QUE" | "STK" => {
                    let items = parse_list(reader, state, e.name().as_ref().to_string())?;
                    embedded = Some(PsValue::List(items));
                }
                "DCT" => {
                    let entries = parse_dict(reader, state)?;
                    embedded = Some(PsValue::Dict(entries));
                }
                "ToString" => obj.to_string = Some(read_text(reader, "ToString")?),
                _ => {
                    // Enums (including RemoteHostMethodId) store their numeric
                    // value directly inside Obj rather than a member set.
                    if let Some(value) = parse_element(reader, &e, state)? {
                        embedded = Some(value);
                    }
                }
            },
            Event::Empty(e) => match e.name().as_ref() {
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    if let Some(rid) = rid
                        && let Some(names) = state.type_names.get(&rid)
                    {
                        obj.type_names.clone_from(names);
                    }
                }
                "ToString" | "Nil" => {}
                _ => {}
            },
            Event::End(e) if e.name().as_ref() == "Obj" => break,
            Event::Eof => {
                return Err(PsrpError::clixml("unexpected EOF inside <Obj>"));
            }
            _ => {}
        }
        buf.clear();
    }

    // If the object had no <MS> but contained an embedded LST / DCT, expose
    // it under the synthetic property name "_value" so callers can still
    // retrieve it easily.
    if let Some(v) = embedded
        && obj.properties.is_empty()
    {
        obj.properties.insert("_value".into(), v);
    }

    Ok(obj)
}

fn parse_member_set(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    obj: &mut PsObject,
    closing_tag: String,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    obj.properties.insert(name, v);
                }
            }
            Event::Empty(e) => match e.name().as_ref() {
                "Nil" => {
                    if let Some(name) = name_attr(&e)? {
                        obj.properties.insert(name, PsValue::Null);
                    }
                }
                "Ref" => {
                    let name = name_attr(&e)?.unwrap_or_default();
                    let rid = ref_ref_id_attr(&e)?;
                    let value = rid
                        .and_then(|r| state.refs.get(&r).cloned())
                        .unwrap_or(PsValue::Null);
                    obj.properties.insert(name, value);
                }
                _ => {}
            },
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside member set")),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_list(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    closing_tag: String,
) -> Result<Vec<PsValue>> {
    let mut items = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(v) = parse_element(reader, &e, state)? {
                    items.push(v);
                }
            }
            Event::Empty(e) => {
                if let Some(v) = parse_empty(&e, state)? {
                    items.push(v);
                }
            }
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside list")),
            _ => {}
        }
        buf.clear();
    }
    Ok(items)
}

fn parse_dict(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<Vec<(PsValue, PsValue)>> {
    let mut entries = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "En" => {
                let (k, v) = parse_dict_entry(reader, state)?;
                entries.push((k, v));
            }
            Event::End(e) if e.name().as_ref() == "DCT" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <DCT>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

fn parse_dict_entry(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<(PsValue, PsValue)> {
    let mut key = PsValue::Null;
    let mut val = PsValue::Null;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    match name.as_str() {
                        "Key" => key = v,
                        "Value" => val = v,
                        _ => {}
                    }
                }
            }
            Event::Empty(e) if e.name().as_ref() == "Nil" => {
                let name = name_attr(&e)?.unwrap_or_default();
                match name.as_str() {
                    "Key" => key = PsValue::Null,
                    "Value" => val = PsValue::Null,
                    _ => {}
                }
            }
            Event::End(e) if e.name().as_ref() == "En" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <En>")),
            _ => {}
        }
        buf.clear();
    }
    Ok((key, val))
}

fn parse_type_names(reader: &mut Reader<&[u8]>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "T" => {
                let text = read_text(reader, "T")?;
                out.push(text);
            }
            Event::End(e) if e.name().as_ref() == "TN" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <TN>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn read_text(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut out = String::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Text(t) => {
                out.push_str(&t);
            }
            Event::GeneralRef(r) => {
                if let Some(c) = r
                    .resolve_char_ref()
                    .map_err(|e| PsrpError::clixml(e.to_string()))?
                {
                    out.push(c);
                } else {
                    let name: &str = r.as_ref();
                    match quick_xml::escape::resolve_predefined_entity(name) {
                        Some(s) => out.push_str(s),
                        None => {
                            return Err(PsrpError::clixml(format!(
                                "unknown entity reference &{name};"
                            )));
                        }
                    }
                }
            }
            Event::CData(c) => {
                out.push_str(c.as_ref());
            }
            Event::End(e) if e.name().as_ref() == closing => break,
            Event::Eof => {
                return Err(PsrpError::clixml(format!("EOF reading <{closing}>")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(decode_pwsh_escapes(&out))
}

/// Drain everything up to the end tag that closes the current element.
///
/// Iterative on purpose — this is the escape hatch for *unknown*
/// elements, so it must stay bounded by the input size rather than by
/// the stack. The counter saturates instead of wrapping so that a
/// pathologically long run of start tags cannot overflow it.
fn skip_to_end(reader: &mut Reader<&[u8]>) -> Result<()> {
    let mut depth: usize = 1;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(_) => depth = depth.saturating_add(1),
            Event::End(_) => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// Decode `_xHHHH_` escapes that Windows PowerShell emits for control chars.
fn decode_pwsh_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let len = bytes.len();
    while i < len {
        // Fast path: look for the `_xHHHH_` pattern at the current byte.
        if i + 7 <= len
            && bytes[i] == b'_'
            && bytes[i + 1] == b'x'
            && bytes[i + 6] == b'_'
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 2..i + 6])
            && let Ok(code) = u32::from_str_radix(hex, 16)
            && let Some(c) = char::from_u32(code)
        {
            out.push(c);
            i += 7;
            continue;
        }
        // Otherwise copy the next UTF-8 character verbatim.
        let ch = s[i..].chars().next().expect("in-bounds char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    /// Regression (found while fuzzing `clixml_decoder`): the parser is
    /// recursive and the document is attacker-controlled, so ~10 KiB of
    /// `<Obj><MS>` used to overflow the stack and abort the process.
    #[test]
    fn deep_nesting_is_rejected_not_fatal() {
        use super::super::parse_clixml;
        use super::MAX_NESTING_DEPTH;

        let deep = |n: usize| "<Obj><MS>".repeat(n) + "<Nil/>" + &"</MS></Obj>".repeat(n);

        // Comfortably inside the limit: still parses.
        parse_clixml(&deep(MAX_NESTING_DEPTH as usize / 2)).expect("shallow document");

        // Past it: a structured error, never a crash.
        let err = parse_clixml(&deep(MAX_NESTING_DEPTH as usize + 5))
            .expect_err("over-deep document must be rejected");
        assert!(
            err.to_string().contains("nested deeper"),
            "unexpected error: {err}"
        );

        // And the pathological case that used to abort the process.
        assert!(parse_clixml(&deep(20_000)).is_err());
    }

    // Regression (found by the `clixml_encode_decode` fuzz target):
    // attribute values used to be taken raw, so a property name holding
    // an XML metacharacter came back still escaped — and the encoder
    // then escaped it again on the next hop.
    #[test]
    fn property_names_are_xml_unescaped() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let value = PsValue::Object(
            PsObject::new()
                .with("a<b", PsValue::I32(1))
                .with("x&y", PsValue::I32(2))
                .with("q\"r", PsValue::I32(3)),
        );

        let xml = to_clixml(&value);
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value, "property names were mangled");

        // And the damage must not compound across hops.
        let again = parse_clixml(&to_clixml(&decoded[0])).expect("decodes");
        assert_eq!(again[0], value);
    }

    #[test]
    fn property_names_decode_pwsh_escapes() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        // `escape` turns control characters in a name into `_xHHHH_`;
        // the decoder has to turn them back.
        let value = PsValue::Object(PsObject::new().with("a\u{1}b", PsValue::Null));
        let xml = to_clixml(&value);
        assert!(xml.contains("_x0001_"), "encoder did not escape: {xml}");
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value);
    }

    use super::super::encode::to_clixml;
    use super::*;

    #[test]
    fn primitives() {
        let cases = vec![
            ("<S>hi</S>", PsValue::String("hi".into())),
            ("<I32>-5</I32>", PsValue::I32(-5)),
            ("<I64>99</I64>", PsValue::I64(99)),
            ("<B>true</B>", PsValue::Bool(true)),
            ("<B>false</B>", PsValue::Bool(false)),
            ("<Db>1.5</Db>", PsValue::Double(1.5)),
            ("<Nil/>", PsValue::Null),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn double_special_values() {
        assert!(
            matches!(parse_clixml("<Db>NaN</Db>").unwrap()[0], PsValue::Double(v) if v.is_nan())
        );
        assert!(matches!(
            parse_clixml("<Db>Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_positive()
        ));
        assert!(matches!(
            parse_clixml("<Db>-Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_negative()
        ));
    }

    #[test]
    fn bool_accepts_1_and_0() {
        assert_eq!(parse_clixml("<B>1</B>").unwrap()[0], PsValue::Bool(true));
        assert_eq!(parse_clixml("<B>0</B>").unwrap()[0], PsValue::Bool(false));
    }

    #[test]
    fn bad_bool_errors() {
        assert!(parse_clixml("<B>maybe</B>").is_err());
    }

    #[test]
    fn bad_int_errors() {
        assert!(parse_clixml("<I32>not-a-number</I32>").is_err());
        assert!(parse_clixml("<I64>xx</I64>").is_err());
        assert!(parse_clixml("<Db>oops</Db>").is_err());
    }

    #[test]
    fn escapes_and_bom() {
        let xml = "\u{FEFF}  <S>&lt;hi&amp;&gt;</S>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got[0], PsValue::String("<hi&>".into()));
    }

    #[test]
    fn pwsh_escape_decode() {
        let got = parse_clixml("<S>ab_x0001_cd</S>").unwrap();
        assert_eq!(got[0], PsValue::String("ab\u{0001}cd".into()));
    }

    #[test]
    fn remote_host_method_enum_keeps_its_numeric_value() {
        let xml = r#"<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T><T>System.Enum</T></TN><ToString>SetCursorPosition</ToString><I32>32</I32></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let obj = got[0].properties().unwrap();
        assert_eq!(obj.get("_value"), Some(&PsValue::I32(32)));
        if let PsValue::Object(obj) = &got[0] {
            assert_eq!(obj.to_string.as_deref(), Some("SetCursorPosition"));
        }
    }

    #[test]
    fn object_with_member_set() {
        let xml = r#"<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T></TN><MS><S N="Name">svchost</S><I32 N="Id">42</I32><Nil N="Maybe"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.type_names,
            vec!["System.Diagnostics.Process".to_string()]
        );
        assert_eq!(obj.get("Name"), Some(&PsValue::String("svchost".into())));
        assert_eq!(obj.get("Id"), Some(&PsValue::I32(42)));
        assert_eq!(obj.get("Maybe"), Some(&PsValue::Null));
    }

    #[test]
    fn object_with_list_and_dict() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><I32>2</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.get("_value"),
            Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)]))
        );
    }

    #[test]
    fn tnref_resolution() {
        // Outer object defines TN with RefId=0. Inner object references it via TNRef.
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
            assert_eq!(o.get("n"), Some(&PsValue::I32(7)));
        } else {
            panic!();
        }
    }

    #[test]
    fn ref_resolution() {
        let xml = r#"<Obj RefId="abc"><MS><S N="k">v</S></MS></Obj><Ref RefId="abc"/>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn dangling_ref_becomes_null() {
        let got = parse_clixml(r#"<Ref RefId="missing"/>"#).unwrap();
        assert_eq!(got[0], PsValue::Null);
    }

    #[test]
    fn unknown_elements_are_skipped() {
        let xml =
            r#"<Obj RefId="0"><UnknownThing><nested/></UnknownThing><MS><S N="k">v</S></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn roundtrip_complex_object() {
        let obj = PsObject {
            type_names: vec!["Foo".into(), "Bar".into()],
            to_string: None,
            properties: {
                let mut p = indexmap::IndexMap::new();
                p.insert("name".into(), PsValue::String("n".into()));
                p.insert("count".into(), PsValue::I32(3));
                p.insert("flag".into(), PsValue::Bool(true));
                p.insert("empty".into(), PsValue::Null);
                p.insert(
                    "tags".into(),
                    PsValue::List(vec![
                        PsValue::String("a".into()),
                        PsValue::String("b".into()),
                    ]),
                );
                p
            },
        };
        let xml = to_clixml(&PsValue::Object(obj.clone()));
        let got = parse_clixml(&xml).unwrap();
        let got_obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!(),
        };
        assert_eq!(got_obj.type_names, obj.type_names);
        assert_eq!(got_obj.get("name"), obj.properties.get("name"));
        assert_eq!(got_obj.get("count"), obj.properties.get("count"));
        assert_eq!(got_obj.get("flag"), obj.properties.get("flag"));
        assert_eq!(got_obj.get("empty"), Some(&PsValue::Null));
        // Embedded list comes back as an object whose _value is the list.
        if let Some(PsValue::Object(tags_obj)) = got_obj.get("tags") {
            assert_eq!(
                tags_obj.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::String("a".into()),
                    PsValue::String("b".into())
                ]))
            );
        } else {
            panic!("expected tags to be an object wrapping a list");
        }
    }

    #[test]
    fn cdata_section_decoded() {
        let got = parse_clixml("<S><![CDATA[hello & <world>]]></S>").unwrap();
        assert_eq!(got[0], PsValue::String("hello & <world>".into()));
    }

    #[test]
    fn top_level_ref_with_content_resolves() {
        // Non-self-closing `<Ref RefId="..">…</Ref>` at top level.
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Ref RefId="a">ignored</Ref>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn empty_obj_body_produces_empty_object() {
        let got = parse_clixml("<Obj RefId=\"0\"></Obj>").unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert!(o.properties.is_empty());
            assert!(o.type_names.is_empty());
        } else {
            panic!();
        }
    }

    #[test]
    fn props_element_is_treated_like_ms() {
        let xml = r#"<Obj RefId="0"><Props><S N="k">v</S></Props></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn pwsh_escape_roundtrip() {
        assert_eq!(decode_pwsh_escapes("_x0041_BC"), "ABC");
        assert_eq!(decode_pwsh_escapes("no escapes here"), "no escapes here");
        assert_eq!(
            decode_pwsh_escapes("_xZZZZ_"),
            "_xZZZZ_",
            "invalid hex passes through"
        );
        assert_eq!(
            decode_pwsh_escapes("café"),
            "café",
            "multi-byte chars preserved"
        );
    }

    #[test]
    fn extended_primitives() {
        // SB (i8), By (u8), I16, U16, U32, U64
        let cases: Vec<(&str, PsValue)> = vec![
            ("<SB>-128</SB>", PsValue::I8(-128)),
            ("<By>255</By>", PsValue::U8(255)),
            ("<I16>-32000</I16>", PsValue::I16(-32000)),
            ("<U16>65535</U16>", PsValue::U16(65535)),
            ("<U32>4000000000</U32>", PsValue::U32(4_000_000_000)),
            ("<U64>18446744073709551615</U64>", PsValue::U64(u64::MAX)),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn extended_primitive_errors() {
        assert!(parse_clixml("<SB>not_int</SB>").is_err());
        assert!(parse_clixml("<By>-1</By>").is_err());
        assert!(parse_clixml("<I16>99999</I16>").is_err());
        assert!(parse_clixml("<U16>-1</U16>").is_err());
        assert!(parse_clixml("<U32>-1</U32>").is_err());
        assert!(parse_clixml("<U64>not_a_number</U64>").is_err());
    }

    #[test]
    fn char_primitive() {
        let got = parse_clixml("<C>65</C>").unwrap();
        assert_eq!(got[0], PsValue::Char('A'));
    }

    #[test]
    fn char_invalid_code_point() {
        // 0xD800 is a surrogate, not a valid char
        assert!(parse_clixml("<C>55296</C>").is_err());
        // Not a number
        assert!(parse_clixml("<C>abc</C>").is_err());
    }

    #[test]
    fn base64_primitive() {
        // "aGVsbG8=" = "hello"
        let got = parse_clixml("<BA>aGVsbG8=</BA>").unwrap();
        assert_eq!(got[0], PsValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn base64_invalid() {
        assert!(parse_clixml("<BA>!!!not-base64!!!</BA>").is_err());
    }

    #[test]
    fn guid_primitive() {
        let got = parse_clixml("<G>12345678-1234-1234-1234-123456789abc</G>").unwrap();
        if let PsValue::Guid(g) = &got[0] {
            assert_eq!(g.to_string(), "12345678-1234-1234-1234-123456789abc");
        } else {
            panic!("expected Guid");
        }
    }

    #[test]
    fn guid_invalid() {
        assert!(parse_clixml("<G>not-a-guid</G>").is_err());
    }

    #[test]
    fn datetime_and_duration() {
        let got = parse_clixml("<DT>2024-01-01T00:00:00Z</DT>").unwrap();
        assert_eq!(
            got[0],
            PsValue::DateTime("2024-01-01T00:00:00Z".to_string())
        );
        let got = parse_clixml("<TS>P1DT2H</TS>").unwrap();
        assert_eq!(got[0], PsValue::Duration("P1DT2H".to_string()));
    }

    #[test]
    fn version_uri_xml_scriptblock_securestring() {
        let cases = vec![
            ("<Version>5.1</Version>", PsValue::Version("5.1".into())),
            (
                "<URI>http://example.com</URI>",
                PsValue::Uri("http://example.com".into()),
            ),
            (
                "<XD>some xml data</XD>",
                PsValue::Xml("some xml data".into()),
            ),
            (
                "<SCT>Get-Process</SCT>",
                PsValue::ScriptBlock("Get-Process".into()),
            ),
            (
                "<SS>encrypted</SS>",
                PsValue::SecureString("encrypted".into()),
            ),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn decimal_primitive() {
        let got = parse_clixml("<D>123.456</D>").unwrap();
        assert_eq!(got[0], PsValue::Decimal("123.456".to_string()));
    }

    #[test]
    fn single_float() {
        let got = parse_clixml("<Sg>1.5</Sg>").unwrap();
        if let PsValue::F32(v) = got[0] {
            assert!((v - 1.5).abs() < f32::EPSILON);
        } else {
            panic!("expected F32");
        }
    }

    #[test]
    fn single_float_special() {
        let got = parse_clixml("<Sg>NaN</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_nan()));
        let got = parse_clixml("<Sg>Infinity</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_infinite()));
    }

    #[test]
    fn single_float_error() {
        assert!(parse_clixml("<Sg>not-float</Sg>").is_err());
    }

    #[test]
    fn unknown_top_level_element_skipped() {
        let xml = "<FutureTag><nested>data</nested></FutureTag><I32>42</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(42));
    }

    #[test]
    fn unknown_self_closing_element_skipped() {
        let xml = "<UnknownThing/><I32>7</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(7));
    }

    #[test]
    fn empty_s_tag_self_closing() {
        let got = parse_clixml("<S/>").unwrap();
        assert_eq!(got[0], PsValue::String(String::new()));
    }

    #[test]
    fn eof_inside_obj_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><MS>").is_err());
    }

    #[test]
    fn eof_inside_list_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><LST><I32>1</I32>").is_err());
    }

    #[test]
    fn eof_inside_dict_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><DCT><En>").is_err());
    }

    #[test]
    fn eof_inside_text_is_error() {
        assert!(parse_clixml("<S>unclosed").is_err());
    }

    #[test]
    fn dict_entry_with_nil_key_and_value() {
        let xml = r#"<Obj RefId="0"><DCT><En><Nil N="Key"/><Nil N="Value"/></En></DCT></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], (PsValue::Null, PsValue::Null));
            } else {
                panic!("expected dict");
            }
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn ref_inside_member_set() {
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Obj RefId="b"><MS><Ref N="copy" RefId="a"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.get("copy"), Some(&got[0]));
        } else {
            panic!();
        }
    }

    #[test]
    fn ie_que_stk_treated_as_list() {
        for tag in ["IE", "QUE", "STK"] {
            let xml = format!(r#"<Obj RefId="0"><{tag}><I32>1</I32><I32>2</I32></{tag}></Obj>"#);
            let got = parse_clixml(&xml).unwrap();
            if let PsValue::Object(o) = &got[0] {
                assert_eq!(
                    o.get("_value"),
                    Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)])),
                    "{tag} should be treated as list"
                );
            } else {
                panic!("{tag} should produce object");
            }
        }
    }

    #[test]
    fn tnref_self_closing_in_obj() {
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
        } else {
            panic!();
        }
    }

    #[test]
    fn nil_inside_list() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><Nil/><I32>3</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(
                o.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::I32(1),
                    PsValue::Null,
                    PsValue::I32(3)
                ]))
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn dict_roundtrip() {
        let v = PsValue::Dict(vec![
            (PsValue::String("k1".into()), PsValue::I32(1)),
            (PsValue::String("k2".into()), PsValue::String("v".into())),
        ]);
        let xml = to_clixml(&v);
        let got = parse_clixml(&xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, PsValue::String("k1".into()));
                assert_eq!(entries[0].1, PsValue::I32(1));
            } else {
                panic!("dict lost");
            }
        } else {
            panic!();
        }
    }
}
