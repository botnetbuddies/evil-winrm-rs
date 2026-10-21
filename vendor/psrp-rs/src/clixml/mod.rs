//! CLIXML (MS-PSRP §2.2.5) — types and (de)serialization.
//!
//! This module owns every CLIXML value that `psrp-rs` can emit or parse.
//! Scope:
//!
//! * Full primitive set from MS-PSRP §2.2.5.1 — `<S>`, `<C>`, `<B>`,
//!   `<DT>`, `<TS>`, `<By>`/`<SB>`, `<U16>`/`<I16>`, `<U32>`/`<I32>`,
//!   `<U64>`/`<I64>`, `<Sg>`/`<Db>`, `<D>`, `<BA>`, `<G>`, `<URI>`,
//!   `<Version>`, `<XD>`, `<SCT>`, `<SS>`, `<Nil/>`.
//! * Complex types — `<Obj>` with member sets (`<MS>` / `<Props>`),
//!   `<LST>` / `<IE>` / `<QUE>` / `<STK>`, `<DCT>`.
//! * Reference resolution — `<Ref>` and `<TNRef>` look up previously
//!   seen ids in the current `parse_clixml` call.
//!
//! Unknown or unsupported XML is skipped on decode rather than failing.

pub(crate) mod decode;
pub(crate) mod encode;

pub use decode::{MAX_NESTING_DEPTH, parse_clixml};
pub use encode::{RefIdAllocator, escape, ps_enum, ps_host_info_null, to_clixml};

use indexmap::IndexMap;
use uuid::Uuid;

/// A decoded CLIXML value.
///
/// Variants cover the full MS-PSRP primitive set plus complex types.
/// Integer, floating-point, and date/time types are distinct so that
/// round-tripping through PowerShell preserves the exact CLIXML tag.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PsValue {
    /// `<Nil/>` or a missing value.
    Null,
    /// `<B>true</B>` / `<B>false</B>`.
    Bool(bool),
    /// `<SB>…</SB>` — signed byte.
    I8(i8),
    /// `<By>…</By>` — unsigned byte.
    U8(u8),
    /// `<I16>…</I16>`.
    I16(i16),
    /// `<U16>…</U16>`.
    U16(u16),
    /// `<I32>…</I32>`.
    I32(i32),
    /// `<U32>…</U32>`.
    U32(u32),
    /// `<I64>…</I64>`.
    I64(i64),
    /// `<U64>…</U64>`.
    U64(u64),
    /// `<Sg>…</Sg>` — single-precision float.
    F32(f32),
    /// `<Db>…</Db>` — double-precision float.
    Double(f64),
    /// `<D>…</D>` — .NET `Decimal`. Stored as its decimal string so
    /// we don't drag in another crate for high-precision arithmetic.
    Decimal(String),
    /// `<C>…</C>` — single UTF-16 code unit.
    Char(char),
    /// `<S>…</S>` — UTF-8 string.
    String(String),
    /// `<BA>…</BA>` — byte array, transported as base64 on the wire.
    Bytes(Vec<u8>),
    /// `<DT>…</DT>` — .NET `DateTime` serialised as ISO-8601.
    ///
    /// Stored as a string so no date crate is needed. Use
    /// `chrono::DateTime::parse_from_rfc3339` on the callers' side to
    /// convert.
    DateTime(String),
    /// `<TS>…</TS>` — .NET `TimeSpan` serialised as
    /// `[-][d.]hh:mm:ss[.fffffff]` or an ISO-8601 duration.
    Duration(String),
    /// `<G>…</G>` — .NET `Guid`.
    Guid(Uuid),
    /// `<Version>…</Version>` — .NET `System.Version`.
    Version(String),
    /// `<URI>…</URI>` — `System.Uri`.
    Uri(String),
    /// `<XD>…</XD>` — `System.Xml.XmlDocument` or fragment.
    Xml(String),
    /// `<SCT>…</SCT>` — PowerShell script block source.
    ScriptBlock(String),
    /// `<SS>…</SS>` — a `SecureString`.
    ///
    /// When transmitted to a server that has negotiated a session key,
    /// the value is encrypted client-side via AES-CBC + base64 before
    /// hitting the wire. Decoding an `<SS>` that arrived from a server
    /// without a session key yields a [`PsValue::SecureString`] whose
    /// contents are the raw bytes (undecryptable).
    SecureString(String),
    /// `<LST>` / `<IE>` / `<QUE>` / `<STK>`.
    List(Vec<PsValue>),
    /// `<DCT>` with `<En>` / `<Key>` / `<Value>` entries.
    Dict(Vec<(PsValue, PsValue)>),
    /// A wrapped `<Obj>` carrying a member set `<MS>`.
    Object(PsObject),
}

impl PsValue {
    /// Get a string if this value is one of the string-like variants
    /// (`String`, `Version`, `Uri`, `Xml`, `ScriptBlock`, `Decimal`,
    /// `DateTime`, `Duration`, `SecureString`).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s)
            | Self::Version(s)
            | Self::Uri(s)
            | Self::Xml(s)
            | Self::ScriptBlock(s)
            | Self::Decimal(s)
            | Self::DateTime(s)
            | Self::Duration(s)
            | Self::SecureString(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get an `i32` if this value is one of the signed integer variants,
    /// lossily narrowing where necessary.
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I8(v) => Some(i32::from(*v)),
            Self::I16(v) => Some(i32::from(*v)),
            Self::I32(v) => Some(*v),
            Self::I64(v) => i32::try_from(*v).ok(),
            Self::U8(v) => Some(i32::from(*v)),
            Self::U16(v) => Some(i32::from(*v)),
            Self::U32(v) => i32::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get an `i64` if this value is any integer variant.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I8(v) => Some(i64::from(*v)),
            Self::I16(v) => Some(i64::from(*v)),
            Self::I32(v) => Some(i64::from(*v)),
            Self::I64(v) => Some(*v),
            Self::U8(v) => Some(i64::from(*v)),
            Self::U16(v) => Some(i64::from(*v)),
            Self::U32(v) => Some(i64::from(*v)),
            Self::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get a `bool` if this value is one, else `None`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Access the extended member set if this value is an object.
    #[must_use]
    pub fn properties(&self) -> Option<&IndexMap<String, PsValue>> {
        if let Self::Object(o) = self {
            Some(&o.properties)
        } else {
            None
        }
    }

    /// Return the type-names hierarchy if this is an object with a `<TN>`.
    #[must_use]
    pub fn type_names(&self) -> Option<&[String]> {
        if let Self::Object(o) = self {
            Some(&o.type_names)
        } else {
            None
        }
    }
}

/// A PSObject with named properties.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PsObject {
    /// Extended member set (`<MS>`), ordered.
    pub properties: IndexMap<String, PsValue>,
    /// Type hierarchy from `<TN>` (most-derived first), if any.
    pub type_names: Vec<String>,
    /// Optional `<ToString>` display representation.
    pub to_string: Option<String>,
}

impl PsObject {
    /// Create an empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a property, returning `self` for builder chains.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: PsValue) -> Self {
        self.properties.insert(name.into(), value);
        self
    }

    /// Attach a type-name hierarchy (most-derived first).
    #[must_use]
    pub fn with_type_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.type_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// Look up a property by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PsValue> {
        self.properties.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_accessors() {
        assert_eq!(PsValue::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(PsValue::Version("5.1".into()).as_str(), Some("5.1"));
        assert_eq!(PsValue::Uri("http://x".into()).as_str(), Some("http://x"));
        assert_eq!(PsValue::Decimal("1.5".into()).as_str(), Some("1.5"));
        assert_eq!(PsValue::I32(5).as_str(), None);
    }

    #[test]
    fn integer_accessors() {
        assert_eq!(PsValue::I8(-1).as_i32(), Some(-1));
        assert_eq!(PsValue::U8(255).as_i32(), Some(255));
        assert_eq!(PsValue::I16(-100).as_i32(), Some(-100));
        assert_eq!(PsValue::U16(65_535).as_i32(), Some(65_535));
        assert_eq!(PsValue::I32(42).as_i32(), Some(42));
        assert_eq!(PsValue::I64(i64::MAX).as_i32(), None);
        assert_eq!(PsValue::I64(42).as_i64(), Some(42));
        assert_eq!(PsValue::U64(u64::MAX).as_i64(), None);
        assert_eq!(PsValue::String("x".into()).as_i32(), None);
    }

    #[test]
    fn bool_accessor() {
        assert_eq!(PsValue::Bool(true).as_bool(), Some(true));
        assert_eq!(PsValue::I32(1).as_bool(), None);
    }

    #[test]
    fn object_accessors() {
        let obj = PsObject::new()
            .with("Name", PsValue::String("Alice".into()))
            .with_type_names(["Foo", "Bar"]);
        let v = PsValue::Object(obj);
        assert!(v.properties().is_some());
        assert_eq!(
            v.type_names(),
            Some(&["Foo".to_string(), "Bar".to_string()][..])
        );
        assert_eq!(
            v.properties()
                .unwrap()
                .get("Name")
                .and_then(PsValue::as_str),
            Some("Alice")
        );
        assert!(PsValue::Null.properties().is_none());
        assert!(PsValue::Null.type_names().is_none());
    }

    #[test]
    fn as_str_returns_none_for_non_string_variants() {
        assert_eq!(PsValue::I32(5).as_str(), None);
        assert_eq!(PsValue::Bool(true).as_str(), None);
        assert_eq!(PsValue::Null.as_str(), None);
        assert_eq!(PsValue::List(vec![]).as_str(), None);
        assert_eq!(PsValue::Double(1.0).as_str(), None);
    }

    #[test]
    fn as_str_covers_all_string_like_variants() {
        assert_eq!(PsValue::Xml("<r/>".into()).as_str(), Some("<r/>"));
        assert_eq!(PsValue::ScriptBlock("Get-X".into()).as_str(), Some("Get-X"));
        assert_eq!(
            PsValue::DateTime("2024-01-01".into()).as_str(),
            Some("2024-01-01")
        );
        assert_eq!(PsValue::Duration("P1D".into()).as_str(), Some("P1D"));
        assert_eq!(PsValue::SecureString("ss".into()).as_str(), Some("ss"));
    }

    #[test]
    fn as_i32_overflow_returns_none() {
        assert_eq!(PsValue::U32(u32::MAX).as_i32(), None);
        assert_eq!(PsValue::I64(i64::MAX).as_i32(), None);
        assert_eq!(PsValue::U64(100).as_i32(), None); // U64 not in match
    }

    #[test]
    fn as_i64_overflow_returns_none() {
        assert_eq!(PsValue::U64(u64::MAX).as_i64(), None);
        assert_eq!(PsValue::Bool(true).as_i64(), None);
        assert_eq!(PsValue::Null.as_i64(), None);
    }

    #[test]
    fn as_i64_covers_all_integer_variants() {
        assert_eq!(PsValue::I8(-1).as_i64(), Some(-1));
        assert_eq!(PsValue::U8(200).as_i64(), Some(200));
        assert_eq!(PsValue::I16(-1000).as_i64(), Some(-1000));
        assert_eq!(PsValue::U16(60000).as_i64(), Some(60000));
        assert_eq!(PsValue::U32(4_000_000_000).as_i64(), Some(4_000_000_000));
    }

    #[test]
    fn properties_and_type_names_on_non_objects() {
        assert!(PsValue::I32(1).properties().is_none());
        assert!(PsValue::String("x".into()).properties().is_none());
        assert!(PsValue::List(vec![]).properties().is_none());
        assert!(PsValue::I32(1).type_names().is_none());
        assert!(PsValue::String("x".into()).type_names().is_none());
        assert!(PsValue::Bool(false).type_names().is_none());
    }
}
