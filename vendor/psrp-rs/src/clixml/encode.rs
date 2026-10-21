//! CLIXML encoder.
//!
//! Every `<Obj>` element in the output carries a monotonic `RefId` issued
//! by [`RefIdAllocator`] so the decoder on the other side can resolve
//! back-references. Each call to [`to_clixml`] gets its own allocator —
//! references are scoped to the top-level call.

use std::cell::Cell;

use super::{PsObject, PsValue};

/// Serialize a [`PsValue`] into a CLIXML fragment (no `<Objs>` wrapper).
#[must_use]
pub fn to_clixml(value: &PsValue) -> String {
    let alloc = RefIdAllocator::new();
    let mut out = String::new();
    write_value_with(&mut out, value, None, &alloc);
    out
}

/// Allocator for monotonically increasing `RefId` values.
///
/// Callers that build CLIXML in multiple stages (e.g. the pipeline
/// creation XML, which is assembled field-by-field) can instantiate
/// their own allocator and thread it through the helpers so the whole
/// document uses a single numbering scheme.
#[derive(Debug)]
pub struct RefIdAllocator {
    next: Cell<u32>,
}

impl RefIdAllocator {
    /// Start issuing ids from `0`.
    #[must_use]
    pub fn new() -> Self {
        Self { next: Cell::new(0) }
    }

    /// Start issuing ids from `start` — useful when two allocator-free
    /// XML fragments need to be concatenated without overlapping.
    #[must_use]
    pub fn starting_at(start: u32) -> Self {
        Self {
            next: Cell::new(start),
        }
    }

    /// Allocate the next id.
    pub fn next(&self) -> u32 {
        let v = self.next.get();
        self.next.set(v + 1);
        v
    }
}

impl Default for RefIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Write a value threading a caller-owned [`RefIdAllocator`] through
/// nested objects.
pub(crate) fn write_value_with(
    out: &mut String,
    value: &PsValue,
    name: Option<&str>,
    alloc: &RefIdAllocator,
) {
    match value {
        PsValue::Null => write_simple(out, "Nil", "", name, true),
        PsValue::Bool(b) => write_simple(out, "B", if *b { "true" } else { "false" }, name, false),
        PsValue::I8(v) => write_simple(out, "SB", &v.to_string(), name, false),
        PsValue::U8(v) => write_simple(out, "By", &v.to_string(), name, false),
        PsValue::I16(v) => write_simple(out, "I16", &v.to_string(), name, false),
        PsValue::U16(v) => write_simple(out, "U16", &v.to_string(), name, false),
        PsValue::I32(v) => write_simple(out, "I32", &v.to_string(), name, false),
        PsValue::U32(v) => write_simple(out, "U32", &v.to_string(), name, false),
        PsValue::I64(v) => write_simple(out, "I64", &v.to_string(), name, false),
        PsValue::U64(v) => write_simple(out, "U64", &v.to_string(), name, false),
        PsValue::F32(v) => write_simple(out, "Sg", &format_float(*v as f64), name, false),
        PsValue::Double(v) => write_simple(out, "Db", &format_float(*v), name, false),
        PsValue::Decimal(s) => write_simple(out, "D", &escape(s), name, false),
        PsValue::Char(c) => write_simple(out, "C", &(*c as u32).to_string(), name, false),
        PsValue::String(s) => write_simple(out, "S", &escape(s), name, false),
        PsValue::Bytes(b) => write_simple(out, "BA", &base64_encode(b), name, false),
        PsValue::DateTime(s) => write_simple(out, "DT", &escape(s), name, false),
        PsValue::Duration(s) => write_simple(out, "TS", &escape(s), name, false),
        PsValue::Guid(g) => write_simple(out, "G", &g.hyphenated().to_string(), name, false),
        PsValue::Version(s) => write_simple(out, "Version", &escape(s), name, false),
        PsValue::Uri(s) => write_simple(out, "URI", &escape(s), name, false),
        PsValue::Xml(s) => write_simple(out, "XD", &escape(s), name, false),
        PsValue::ScriptBlock(s) => write_simple(out, "SCT", &escape(s), name, false),
        PsValue::SecureString(s) => write_simple(out, "SS", &escape(s), name, false),
        PsValue::List(_) | PsValue::Dict(_) => {
            open_obj(out, name, alloc);
            write_container_body(out, value, alloc);
            out.push_str("</Obj>");
        }
        PsValue::Object(obj) => write_object(out, obj, name, alloc),
    }
}

/// Write the bare `<LST>` / `<DCT>` body of a container, without the
/// enclosing `<Obj>`.
///
/// Split out of [`write_value_with`] because a container stored under an
/// object's synthetic `_value` property is written *inside* that
/// object's `<Obj>`, not wrapped in a second one — which is how the
/// decoder spells it, and therefore the only spelling that round-trips.
/// Returns `false` if `value` is not a container.
fn write_container_body(out: &mut String, value: &PsValue, alloc: &RefIdAllocator) -> bool {
    match value {
        PsValue::List(items) => {
            out.push_str("<LST>");
            for item in items {
                write_value_with(out, item, None, alloc);
            }
            out.push_str("</LST>");
            true
        }
        PsValue::Dict(entries) => {
            out.push_str("<DCT>");
            for (k, v) in entries {
                out.push_str("<En>");
                write_value_with(out, k, Some("Key"), alloc);
                write_value_with(out, v, Some("Value"), alloc);
                out.push_str("</En>");
            }
            out.push_str("</DCT>");
            true
        }
        _ => false,
    }
}

fn format_float(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        format!("{v}")
    }
}

fn write_simple(out: &mut String, tag: &str, body: &str, name: Option<&str>, self_close: bool) {
    if self_close {
        if let Some(n) = name {
            out.push('<');
            out.push_str(tag);
            out.push_str(" N=\"");
            out.push_str(&escape_attr(n));
            out.push_str("\"/>");
        } else {
            out.push('<');
            out.push_str(tag);
            out.push_str("/>");
        }
        return;
    }
    match name {
        Some(n) => {
            out.push('<');
            out.push_str(tag);
            out.push_str(" N=\"");
            out.push_str(&escape_attr(n));
            out.push_str("\">");
            out.push_str(body);
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        None => {
            out.push('<');
            out.push_str(tag);
            out.push('>');
            out.push_str(body);
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
    }
}

fn open_obj(out: &mut String, name: Option<&str>, alloc: &RefIdAllocator) {
    let id = alloc.next();
    match name {
        Some(n) => {
            out.push_str("<Obj N=\"");
            out.push_str(&escape_attr(n));
            out.push_str(&format!("\" RefId=\"{id}\">"));
        }
        None => out.push_str(&format!("<Obj RefId=\"{id}\">")),
    }
}

fn write_object(out: &mut String, obj: &PsObject, name: Option<&str>, alloc: &RefIdAllocator) {
    open_obj(out, name, alloc);
    if !obj.type_names.is_empty() {
        out.push_str(&format!("<TN RefId=\"{}\">", alloc.next()));
        for tn in &obj.type_names {
            out.push_str("<T>");
            out.push_str(&escape(tn));
            out.push_str("</T>");
        }
        out.push_str("</TN>");
    }
    if let Some(ts) = &obj.to_string {
        out.push_str("<ToString>");
        out.push_str(&escape(ts));
        out.push_str("</ToString>");
    }
    // The synthetic "_value" property is rendered as a bare child of
    // the Obj (used for enum encoding via `ps_enum`).
    let value_prop = obj.properties.get("_value").cloned();
    let other_props: Vec<(&String, &PsValue)> = obj
        .properties
        .iter()
        .filter(|(k, _)| k.as_str() != "_value")
        .collect();
    if let Some(v) = &value_prop {
        // A container under `_value` is emitted as a bare `<LST>` /
        // `<DCT>` child. Routing it through `write_value_with` would wrap
        // it in a second `<Obj>`, which the decoder skips as an unknown
        // element — silently dropping the whole container.
        if !write_container_body(out, v, alloc) {
            write_value_with(out, v, None, alloc);
        }
    }
    if !other_props.is_empty() {
        out.push_str("<MS>");
        for (k, v) in other_props {
            write_value_with(out, v, Some(k), alloc);
        }
        out.push_str("</MS>");
    }
    out.push_str("</Obj>");
}

/// Build a `<Obj>` representing a .NET `enum` value with the full type
/// hierarchy that strict PSRP server-side deserialisers expect.
///
/// Output shape (RefId numbering is left to the caller's allocator):
/// ```xml
/// <Obj RefId="…">
///   <TN RefId="…">
///     <T>System.Management.Automation.Runspaces.PSThreadOptions</T>
///     <T>System.Enum</T>
///     <T>System.ValueType</T>
///     <T>System.Object</T>
///   </TN>
///   <ToString>Default</ToString>
///   <I32>0</I32>
/// </Obj>
/// ```
#[must_use]
pub fn ps_enum(enum_type: &str, value_name: &str, integer_value: i32) -> PsValue {
    let mut obj = PsObject::new().with_type_names([
        enum_type.to_string(),
        "System.Enum".to_string(),
        "System.ValueType".to_string(),
        "System.Object".to_string(),
    ]);
    obj.to_string = Some(value_name.to_string());
    // The enum's wire value is a *bare* integer at the root of the
    // object's body — we represent it via a synthetic `_value` property
    // that the encoder treats specially below.
    obj.properties
        .insert("_value".into(), PsValue::I32(integer_value));
    PsValue::Object(obj)
}

/// Build the minimum-viable `HostInfo` object required by an
/// `InitRunspacePool` message — declares "no host" so the server
/// doesn't try to call back into us during the handshake.
#[must_use]
pub fn ps_host_info_null() -> PsValue {
    PsValue::Object(
        PsObject::new()
            .with("_isHostNull", PsValue::Bool(true))
            .with("_isHostUINull", PsValue::Bool(true))
            .with("_isHostRawUINull", PsValue::Bool(true))
            .with("_useRunspaceHost", PsValue::Bool(true)),
    )
}

/// Escape a string for XML **text** content.
///
/// Control characters below 0x20 (except `\t`, `\n`, `\r`, which XML
/// text preserves verbatim) are emitted as PowerShell's `_xHHHH_`
/// escapes.
#[must_use]
pub fn escape(s: &str) -> String {
    escape_inner(s, false)
}

/// Escape a string for an XML **attribute value** (`N="…"`, `RefId="…"`).
///
/// Same as [`escape`] plus `\t`, `\n` and `\r`, which a conforming XML
/// parser replaces with a space during attribute-value normalisation
/// (XML 1.0 §3.3.3). Emitting them literally would therefore silently
/// turn a tab in a property name into a space on the way back.
#[must_use]
pub fn escape_attr(s: &str) -> String {
    escape_inner(s, true)
}

fn escape_inner(s: &str, attribute: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // A literal `_` that would open a `_xHHHH_` sequence has to
            // be escaped itself, or the decoder reads the user's text as
            // an escape: `"9+_x001F_"` would come back as `"9+\u{1f}"`.
            // This is what PowerShell's own serializer does.
            '_' if opens_pwsh_escape(bytes, i) => out.push_str("_x005F_"),
            '\t' | '\n' | '\r' if attribute => {
                out.push_str(&format!("_x{:04X}_", c as u32));
            }
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("_x{:04X}_", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Does a `_xHHHH_` escape sequence start at byte offset `i`?
///
/// Mirrors the pattern `decode_pwsh_escapes` looks for, so the two stay
/// exact inverses of each other.
fn opens_pwsh_escape(bytes: &[u8], i: usize) -> bool {
    i + 7 <= bytes.len()
        && bytes[i] == b'_'
        && bytes[i + 1] == b'x'
        && bytes[i + 6] == b'_'
        && bytes[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
}

/// Minimal, allocation-conscious base64 encoder (standard alphabet).
#[must_use]
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let (chunks, rem) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let b0 = chunk[0] as usize;
        let b1 = chunk[1] as usize;
        let b2 = chunk[2] as usize;
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        out.push(ALPHABET[b2 & 0x3F] as char);
    }
    match rem.len() {
        0 => {}
        1 => {
            let b0 = rem[0] as usize;
            out.push(ALPHABET[b0 >> 2] as char);
            out.push(ALPHABET[(b0 & 0x03) << 4] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = rem[0] as usize;
            let b1 = rem[1] as usize;
            out.push(ALPHABET[b0 >> 2] as char);
            out.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
            out.push(ALPHABET[(b1 & 0x0F) << 2] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

// ---------------------------------------------------------------------------
// Pipeline CreatePipeline XML builder (MS-PSRP §2.2.2.12)
// ---------------------------------------------------------------------------

/// Describes one argument inside a [`PipelineCommandSpec`].
pub(crate) enum PipelineArgSpec<'a> {
    Named { name: &'a str, value: &'a PsValue },
    Positional(&'a PsValue),
    Switch(&'a str),
}

/// Describes one command inside a pipeline, decoupled from
/// `crate::pipeline::Command` so `clixml/` never imports `pipeline`.
pub(crate) struct PipelineCommandSpec<'a> {
    pub name: &'a str,
    pub is_script: bool,
    pub merge_errors_to_output: bool,
    pub args: Vec<PipelineArgSpec<'a>>,
}

/// Write a .NET enum `<Obj>` with a full `<TN>` type-name block.
///
/// Returns the `RefId` allocated for the `<TN>` element so subsequent
/// siblings can emit `<TNRef RefId="…"/>` instead.
fn write_enum_first_in_group(
    out: &mut String,
    name: Option<&str>,
    enum_type: &str,
    to_string: &str,
    value: i32,
    alloc: &RefIdAllocator,
) -> u32 {
    open_obj(out, name, alloc);
    let tn_id = alloc.next();
    out.push_str(&format!("<TN RefId=\"{tn_id}\">"));
    out.push_str("<T>");
    out.push_str(&escape(enum_type));
    out.push_str("</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>");
    out.push_str("</TN>");
    out.push_str("<ToString>");
    out.push_str(&escape(to_string));
    out.push_str("</ToString>");
    out.push_str(&format!("<I32>{value}</I32>"));
    out.push_str("</Obj>");
    tn_id
}

/// Write a .NET enum `<Obj>` with a `<TNRef>` back-reference to an
/// already-emitted `<TN>`.
fn write_enum_with_tnref(
    out: &mut String,
    name: Option<&str>,
    tn_ref_id: u32,
    to_string: &str,
    value: i32,
    alloc: &RefIdAllocator,
) {
    open_obj(out, name, alloc);
    out.push_str(&format!("<TNRef RefId=\"{tn_ref_id}\"/>"));
    out.push_str("<ToString>");
    out.push_str(&escape(to_string));
    out.push_str("</ToString>");
    out.push_str(&format!("<I32>{value}</I32>"));
    out.push_str("</Obj>");
}

/// Build the CLIXML body for a `CreatePipeline` message (MS-PSRP §2.2.2.12).
///
/// Produces exactly the same XML structure that `pypsrp` (Python) and older
/// hand-rolled Rust code emitted — including `TN`/`TNRef` sharing for
/// `PipelineResultTypes` enums and the `Cmds`/`Args` list type.
pub(crate) fn build_create_pipeline_xml(
    no_input: bool,
    add_to_history: bool,
    add_invocation_info: bool,
    commands: &[PipelineCommandSpec<'_>],
) -> String {
    let a = RefIdAllocator::new();
    let mut o = format!("<Obj RefId=\"{}\"><MS>", a.next());

    // ── ROOT: NoInput ───────────────────────────────────────────────
    write_value_with(&mut o, &PsValue::Bool(no_input), Some("NoInput"), &a);

    // ── ROOT: ApartmentState ────────────────────────────────────────
    write_value_with(
        &mut o,
        &ps_enum(
            "System.Management.Automation.Runspaces.ApartmentState",
            "UNKNOWN",
            2,
        ),
        Some("ApartmentState"),
        &a,
    );

    // ── ROOT: RemoteStreamOptions ───────────────────────────────────
    let (so_name, so_val) = if add_invocation_info {
        ("AddInvocationInfo", 15)
    } else {
        ("None", 0)
    };
    write_value_with(
        &mut o,
        &ps_enum(
            "System.Management.Automation.Runspaces.RemoteStreamOptions",
            so_name,
            so_val,
        ),
        Some("RemoteStreamOptions"),
        &a,
    );

    // ── ROOT: AddToHistory ──────────────────────────────────────────
    write_value_with(
        &mut o,
        &PsValue::Bool(add_to_history),
        Some("AddToHistory"),
        &a,
    );

    // ── ROOT: HostInfo ──────────────────────────────────────────────
    write_value_with(&mut o, &ps_host_info_null(), Some("HostInfo"), &a);

    // ── ROOT: PowerShell sub-object ─────────────────────────────────
    open_obj(&mut o, Some("PowerShell"), &a);
    o.push_str("<MS>");
    write_value_with(&mut o, &PsValue::Bool(false), Some("IsNested"), &a);
    write_value_with(&mut o, &PsValue::Null, Some("ExtraCmds"), &a);

    // Cmds list with TN
    let cmds_tn = a.next();
    o.push_str(&format!(
        "<Obj RefId=\"{}\" N=\"Cmds\"><TN RefId=\"{cmds_tn}\"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST>",
        a.next()
    ));

    let prt = "System.Management.Automation.Runspaces.PipelineResultTypes";
    let mut first_prt_tn: Option<u32> = None;

    for c in commands {
        open_obj(&mut o, None, &a);
        o.push_str("<MS>");
        write_value_with(
            &mut o,
            &PsValue::String(c.name.to_string()),
            Some("Cmd"),
            &a,
        );
        write_value_with(&mut o, &PsValue::Bool(c.is_script), Some("IsScript"), &a);
        write_value_with(&mut o, &PsValue::Null, Some("UseLocalScope"), &a);

        // Merge fields — first one gets TN, rest get TNRef
        let (merge_my_name, merge_my_val) = if c.merge_errors_to_output {
            ("Error", 2)
        } else {
            ("None", 0)
        };
        let (merge_to_name, merge_to_val) = if c.merge_errors_to_output {
            ("Output", 1)
        } else {
            ("None", 0)
        };
        for (name, label, val) in [
            ("MergeMyResult", merge_my_name, merge_my_val),
            ("MergeToResult", merge_to_name, merge_to_val),
            ("MergePreviousResults", "None", 0i32),
        ] {
            if let Some(tn_ref) = first_prt_tn {
                write_enum_with_tnref(&mut o, Some(name), tn_ref, label, val, &a);
            } else {
                let tn_id = write_enum_first_in_group(&mut o, Some(name), prt, label, val, &a);
                first_prt_tn = Some(tn_id);
            }
        }

        // Args (uses TNRef to cmds_tn)
        o.push_str(&format!(
            "<Obj RefId=\"{}\" N=\"Args\"><TNRef RefId=\"{cmds_tn}\"/><LST>",
            a.next()
        ));
        for arg in &c.args {
            open_obj(&mut o, None, &a);
            o.push_str("<MS>");
            match arg {
                PipelineArgSpec::Named { name, value } => {
                    write_value_with(&mut o, &PsValue::String((*name).to_string()), Some("N"), &a);
                    write_value_with(&mut o, value, Some("V"), &a);
                }
                PipelineArgSpec::Positional(value) => {
                    write_value_with(&mut o, &PsValue::Null, Some("N"), &a);
                    write_value_with(&mut o, value, Some("V"), &a);
                }
                PipelineArgSpec::Switch(name) => {
                    write_value_with(&mut o, &PsValue::String((*name).to_string()), Some("N"), &a);
                    write_value_with(&mut o, &PsValue::Bool(true), Some("V"), &a);
                }
            }
            o.push_str("</MS></Obj>");
        }
        o.push_str("</LST></Obj>"); // close Args

        // Remaining Merge fields (MergeError..MergeInformation)
        let tn_ref = first_prt_tn.expect("at least one merge field emitted");
        for name in [
            "MergeError",
            "MergeWarning",
            "MergeVerbose",
            "MergeDebug",
            "MergeInformation",
        ] {
            write_enum_with_tnref(&mut o, Some(name), tn_ref, "None", 0, &a);
        }
        o.push_str("</MS></Obj>"); // close Cmd
    }

    o.push_str("</LST></Obj>"); // close Cmds
    write_value_with(&mut o, &PsValue::Null, Some("History"), &a);
    write_value_with(
        &mut o,
        &PsValue::Bool(false),
        Some("RedirectShellErrorOutputPipe"),
        &a,
    );
    o.push_str("</MS></Obj>"); // close PowerShell

    // ROOT: IsNested (at root level too)
    write_value_with(&mut o, &PsValue::Bool(false), Some("IsNested"), &a);
    o.push_str("</MS></Obj>"); // close root
    o
}

/// Decode a base64 string, ignoring whitespace.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == '=' {
            break;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    // Regression (found by the `clixml_encode_decode` fuzz target): a
    // container stored under the synthetic `_value` property used to be
    // written as `<Obj><Obj><LST/></Obj></Obj>`. The decoder skips the
    // inner `<Obj>` as an unknown element, so the list was silently lost
    // on the way back.
    #[test]
    fn value_property_container_is_written_bare() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let mut obj = PsObject::new();
        obj.properties.insert(
            "_value".into(),
            PsValue::List(vec![PsValue::U8(0), PsValue::String("x".into())]),
        );
        let value = PsValue::Object(obj);

        let xml = to_clixml(&value);
        assert_eq!(xml, r#"<Obj RefId="0"><LST><By>0</By><S>x</S></LST></Obj>"#);

        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0], value,
            "container under `_value` did not round-trip"
        );
    }

    /// Regression (found by the `clixml_encode_decode` fuzz target): a
    /// string that already reads like a PowerShell escape used to be
    /// decoded as one, so `"9+_x001F_"` came back as `"9+\u{1f}"`.
    #[test]
    fn literal_pwsh_escape_sequences_survive() {
        use super::super::{PsValue, parse_clixml, to_clixml};

        for text in ["9+_x001F_", "_x005F_", "a_x0041_b", "_x", "_", "__x0041__"] {
            let value = PsValue::String(text.to_string());
            let xml = to_clixml(&value);
            let decoded = parse_clixml(&xml).expect("decodes");
            assert_eq!(decoded[0], value, "{text:?} was mangled via {xml}");

            // And it must be stable, not merely correct once.
            let again = parse_clixml(&to_clixml(&decoded[0])).expect("decodes");
            assert_eq!(again[0], value, "{text:?} drifted on the second hop");
        }
    }

    /// XML attribute-value normalisation turns a literal tab, CR or LF
    /// into a space, so those have to leave as `_xHHHH_` escapes when
    /// they sit inside `N="…"` — but stay literal in element text.
    #[test]
    fn attribute_names_escape_whitespace_but_text_does_not() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let value =
            PsValue::Object(PsObject::new().with("a\tb\nc", PsValue::String("x\ty\nz".into())));
        let xml = to_clixml(&value);
        assert!(xml.contains("_x0009_"), "tab not escaped in name: {xml}");
        assert!(xml.contains("x\ty\nz"), "text was escaped: {xml}");

        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value);
    }

    #[test]
    fn value_property_dict_is_written_bare() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let mut obj = PsObject::new();
        obj.properties.insert(
            "_value".into(),
            PsValue::Dict(vec![(PsValue::String("k".into()), PsValue::I32(7))]),
        );
        let value = PsValue::Object(obj);

        let xml = to_clixml(&value);
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value, "dict under `_value` did not round-trip");
    }

    use super::*;
    use uuid::Uuid;

    #[test]
    fn primitives() {
        assert_eq!(to_clixml(&PsValue::Null), "<Nil/>");
        assert_eq!(to_clixml(&PsValue::Bool(true)), "<B>true</B>");
        assert_eq!(to_clixml(&PsValue::Bool(false)), "<B>false</B>");
        assert_eq!(to_clixml(&PsValue::I32(-7)), "<I32>-7</I32>");
        assert_eq!(to_clixml(&PsValue::I64(42)), "<I64>42</I64>");
        assert_eq!(to_clixml(&PsValue::Double(1.5)), "<Db>1.5</Db>");
        assert_eq!(to_clixml(&PsValue::F32(0.5)), "<Sg>0.5</Sg>");
        assert_eq!(to_clixml(&PsValue::I8(-1)), "<SB>-1</SB>");
        assert_eq!(to_clixml(&PsValue::U8(255)), "<By>255</By>");
        assert_eq!(to_clixml(&PsValue::I16(-1)), "<I16>-1</I16>");
        assert_eq!(to_clixml(&PsValue::U16(65_535)), "<U16>65535</U16>");
        assert_eq!(to_clixml(&PsValue::U32(1)), "<U32>1</U32>");
        assert_eq!(to_clixml(&PsValue::U64(1)), "<U64>1</U64>");
        assert_eq!(to_clixml(&PsValue::Char('A')), "<C>65</C>");
        assert_eq!(to_clixml(&PsValue::Decimal("1.5".into())), "<D>1.5</D>");
    }

    #[test]
    fn string_like_variants() {
        assert_eq!(
            to_clixml(&PsValue::DateTime("2024-01-01T00:00:00".into())),
            "<DT>2024-01-01T00:00:00</DT>"
        );
        assert_eq!(
            to_clixml(&PsValue::Duration("00:00:05".into())),
            "<TS>00:00:05</TS>"
        );
        assert_eq!(
            to_clixml(&PsValue::Version("5.1.0.0".into())),
            "<Version>5.1.0.0</Version>"
        );
        assert_eq!(
            to_clixml(&PsValue::Uri("http://x".into())),
            "<URI>http://x</URI>"
        );
        assert_eq!(
            to_clixml(&PsValue::Xml("<a/>".into())),
            "<XD>&lt;a/&gt;</XD>"
        );
        assert_eq!(
            to_clixml(&PsValue::ScriptBlock("Get-Date".into())),
            "<SCT>Get-Date</SCT>"
        );
        assert_eq!(to_clixml(&PsValue::SecureString("x".into())), "<SS>x</SS>");
    }

    #[test]
    fn guid_encoding() {
        let g = Uuid::parse_str("11112222-3333-4444-5555-666677778888").unwrap();
        assert_eq!(
            to_clixml(&PsValue::Guid(g)),
            "<G>11112222-3333-4444-5555-666677778888</G>"
        );
    }

    #[test]
    fn byte_array_roundtrip() {
        let bytes = vec![0u8, 1, 2, 3, 4, 5];
        let b64 = base64_encode(&bytes);
        assert_eq!(b64, "AAECAwQF");
        assert_eq!(base64_decode(&b64).unwrap(), bytes);
        assert_eq!(
            to_clixml(&PsValue::Bytes(bytes.clone())),
            format!("<BA>{b64}</BA>")
        );
    }

    #[test]
    fn base64_edge_cases() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("  Zm\n9v ").unwrap(), b"foo");
        assert!(base64_decode("!!!").is_none());
    }

    #[test]
    fn double_special_values() {
        assert_eq!(to_clixml(&PsValue::Double(f64::NAN)), "<Db>NaN</Db>");
        assert_eq!(
            to_clixml(&PsValue::Double(f64::INFINITY)),
            "<Db>Infinity</Db>"
        );
        assert_eq!(
            to_clixml(&PsValue::Double(f64::NEG_INFINITY)),
            "<Db>-Infinity</Db>"
        );
    }

    #[test]
    fn string_escaping() {
        let xml = to_clixml(&PsValue::String("<hi & \"world\" 'x'\u{0001}".into()));
        assert!(xml.contains("&lt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;"));
        assert!(xml.contains("&apos;"));
        assert!(xml.contains("_x0001_"));
    }

    #[test]
    fn space_is_not_escaped() {
        let xml = to_clixml(&PsValue::String("a b".into()));
        assert!(!xml.contains("_x0020_"));
        assert!(xml.contains("a b"));
    }

    #[test]
    fn list_encoding() {
        let v = PsValue::List(vec![PsValue::I32(1), PsValue::String("a".into())]);
        let xml = to_clixml(&v);
        assert!(xml.contains("<LST>"));
        assert!(xml.contains("<I32>1</I32>"));
        assert!(xml.contains("<S>a</S>"));
    }

    #[test]
    fn dict_encoding() {
        let v = PsValue::Dict(vec![(PsValue::String("k".into()), PsValue::I32(9))]);
        let xml = to_clixml(&v);
        assert!(xml.contains("<DCT>"));
        assert!(xml.contains("<En>"));
        assert!(xml.contains("N=\"Key\""));
        assert!(xml.contains("N=\"Value\""));
    }

    #[test]
    fn object_encoding_with_typenames_and_tostring() {
        let obj = PsObject::new()
            .with("Name", PsValue::String("Alice".into()))
            .with("Id", PsValue::I32(7))
            .with_type_names(["System.Diagnostics.Process"]);
        let mut obj = obj;
        obj.to_string = Some("alice".into());
        let xml = to_clixml(&PsValue::Object(obj));
        assert!(xml.contains("<TN RefId=\"1\">"));
        assert!(xml.contains("<T>System.Diagnostics.Process</T>"));
        assert!(xml.contains("<ToString>alice</ToString>"));
        assert!(xml.contains("<MS>"));
        assert!(xml.contains("<S N=\"Name\">Alice</S>"));
        assert!(xml.contains("<I32 N=\"Id\">7</I32>"));
    }

    #[test]
    fn nil_with_name() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("Maybe", PsValue::Null),
        ));
        assert!(xml.contains("<Nil N=\"Maybe\"/>"));
    }

    #[test]
    fn refid_allocator() {
        let a = RefIdAllocator::new();
        assert_eq!(a.next(), 0);
        assert_eq!(a.next(), 1);
        assert_eq!(a.next(), 2);
        let b = RefIdAllocator::starting_at(42);
        assert_eq!(b.next(), 42);
        assert_eq!(b.next(), 43);
        let _ = RefIdAllocator::default();
    }

    #[test]
    fn pipeline_xml_single_script_has_one_tn_and_seven_tnref_for_prt() {
        let xml = build_create_pipeline_xml(
            true,
            false,
            true,
            &[PipelineCommandSpec {
                name: "1+1",
                is_script: true,
                merge_errors_to_output: false,
                args: vec![],
            }],
        );
        // Exactly one <TN> for PipelineResultTypes
        let prt = "System.Management.Automation.Runspaces.PipelineResultTypes";
        assert_eq!(
            xml.matches(prt).count(),
            1,
            "PRT type string should appear once (in <TN>)"
        );
        // The first merge field uses <TN>, remaining 7 use <TNRef>
        assert_eq!(
            xml.matches("<TNRef").count(),
            8, // 2 MergeToResult+MergePreviousResults + 5 MergeError..MergeInformation + 1 Args
            "expected 8 TNRef total (7 for PRT enums + 1 for Args list)"
        );
    }

    #[test]
    fn pipeline_xml_args_uses_tnref_to_cmds_list() {
        let xml = build_create_pipeline_xml(
            true,
            false,
            false,
            &[PipelineCommandSpec {
                name: "Get-Process",
                is_script: false,
                merge_errors_to_output: false,
                args: vec![PipelineArgSpec::Named {
                    name: "Name",
                    value: &PsValue::String("svchost".into()),
                }],
            }],
        );
        assert!(xml.contains("N=\"Args\""), "Args field must be present");
        // Args Obj should use <TNRef>, not <TN>
        let args_pos = xml.find("N=\"Args\"").unwrap();
        let after_args = &xml[args_pos..];
        assert!(
            after_args.starts_with("N=\"Args\"><TNRef"),
            "Args should use TNRef to reference the Cmds list TN"
        );
    }

    #[test]
    fn pipeline_xml_two_commands_share_prt_tnref() {
        let xml = build_create_pipeline_xml(
            true,
            false,
            true,
            &[
                PipelineCommandSpec {
                    name: "Get-Process",
                    is_script: false,
                    merge_errors_to_output: false,
                    args: vec![],
                },
                PipelineCommandSpec {
                    name: "Select-Object",
                    is_script: false,
                    merge_errors_to_output: false,
                    args: vec![PipelineArgSpec::Named {
                        name: "First",
                        value: &PsValue::I32(5),
                    }],
                },
            ],
        );
        let prt = "System.Management.Automation.Runspaces.PipelineResultTypes";
        // Still only one TN definition for PRT across both commands
        assert_eq!(xml.matches(prt).count(), 1);
        // 2 commands × 8 merge fields each = 16, minus the first = 15 TNRef for PRT
        // Plus 2 TNRef for Args = 17 total
        assert_eq!(xml.matches("<TNRef").count(), 17);
    }

    #[test]
    fn pipeline_xml_switch_emits_bool_true() {
        let xml = build_create_pipeline_xml(
            true,
            false,
            false,
            &[PipelineCommandSpec {
                name: "Get-Process",
                is_script: false,
                merge_errors_to_output: false,
                args: vec![PipelineArgSpec::Switch("FileVersionInfo")],
            }],
        );
        assert!(xml.contains("<S N=\"N\">FileVersionInfo</S>"));
        assert!(xml.contains("<B N=\"V\">true</B>"));
    }

    #[test]
    fn pipeline_xml_positional_has_nil_name() {
        let xml = build_create_pipeline_xml(
            true,
            false,
            false,
            &[PipelineCommandSpec {
                name: "Get-Process",
                is_script: false,
                merge_errors_to_output: false,
                args: vec![PipelineArgSpec::Positional(&PsValue::String(
                    "svchost".into(),
                ))],
            }],
        );
        assert!(xml.contains("<Nil N=\"N\"/>"));
        assert!(xml.contains("<S N=\"V\">svchost</S>"));
    }
}
