//! Typed accessors for PowerShell record types.
//!
//! A PSRP pipeline emits various "record" objects on non-output streams
//! (`ErrorRecord`, `WarningRecord`, `ProgressRecord`, …). On the wire
//! they're serialized as `PsObject`s with a documented member set. This
//! module offers ergonomic Rust structs over that raw representation
//! while preserving the underlying [`PsValue`] for forward compatibility.

use crate::clixml::{PsObject, PsValue};

/// Convert a `PsValue` into a struct if it matches the expected shape.
pub trait FromPsObject: Sized {
    /// Attempt to build `Self` from the given `PsValue`. Returns `None`
    /// when the value is not a `PsObject` or the required properties are
    /// missing.
    fn from_ps_object(value: &PsValue) -> Option<Self>;
}

fn as_object(value: &PsValue) -> Option<&PsObject> {
    if let PsValue::Object(obj) = value {
        Some(obj)
    } else {
        None
    }
}

fn property_str(obj: &PsObject, name: &str) -> Option<String> {
    obj.get(name).and_then(PsValue::as_str).map(str::to_string)
}

fn property_i32(obj: &PsObject, name: &str) -> Option<i32> {
    obj.get(name).and_then(PsValue::as_i32)
}

/// A PowerShell `ErrorRecord`.
///
/// Every field is optional because some cmdlets only populate a subset
/// and we must not reject records with missing properties.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ErrorRecord {
    /// High-level exception description.
    pub exception: Option<ExceptionInfo>,
    /// `FullyQualifiedErrorId` property.
    pub fully_qualified_error_id: Option<String>,
    /// Structured category (activity / target / reason).
    pub category: Option<ErrorCategoryInfo>,
    /// `ScriptStackTrace` property (multi-line).
    pub script_stack_trace: Option<String>,
    /// Object the command was operating on when the error occurred.
    pub target_object: Option<PsValue>,
    /// `InvocationInfo` property.
    pub invocation_info: Option<InvocationInfo>,
}

/// A decoded `System.Exception` (or descendant).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExceptionInfo {
    pub message: Option<String>,
    pub source: Option<String>,
    pub stack_trace: Option<String>,
    pub inner_exception: Option<Box<ExceptionInfo>>,
    pub type_name: Option<String>,
}

/// A decoded `ErrorCategoryInfo`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ErrorCategoryInfo {
    pub category: Option<i32>,
    pub activity: Option<String>,
    pub reason: Option<String>,
    pub target_name: Option<String>,
    pub target_type: Option<String>,
}

/// A decoded `InvocationInfo`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InvocationInfo {
    pub command_name: Option<String>,
    pub script_name: Option<String>,
    pub line_number: Option<i32>,
    pub offset_in_line: Option<i32>,
    pub position_message: Option<String>,
}

impl FromPsObject for ErrorRecord {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = as_object(value)?;
        Some(Self {
            exception: obj
                .get("Exception")
                .and_then(ExceptionInfo::from_ps_object)
                .or_else(|| {
                    property_str(obj, "Exception").map(|message| ExceptionInfo {
                        message: Some(message),
                        ..ExceptionInfo::default()
                    })
                }),
            fully_qualified_error_id: property_str(obj, "FullyQualifiedErrorId"),
            category: obj
                .get("CategoryInfo")
                .and_then(ErrorCategoryInfo::from_ps_object),
            script_stack_trace: property_str(obj, "ErrorDetails_ScriptStackTrace")
                .or_else(|| property_str(obj, "ScriptStackTrace")),
            target_object: obj.get("TargetObject").cloned(),
            invocation_info: obj
                .get("InvocationInfo")
                .and_then(InvocationInfo::from_ps_object),
        })
    }
}

impl FromPsObject for ExceptionInfo {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = as_object(value)?;
        Some(Self {
            message: property_str(obj, "Message"),
            source: property_str(obj, "Source"),
            stack_trace: property_str(obj, "StackTrace"),
            inner_exception: obj
                .get("InnerException")
                .and_then(ExceptionInfo::from_ps_object)
                .map(Box::new),
            type_name: obj.type_names.first().cloned(),
        })
    }
}

impl FromPsObject for ErrorCategoryInfo {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = as_object(value)?;
        Some(Self {
            category: property_i32(obj, "Category"),
            activity: property_str(obj, "Activity"),
            reason: property_str(obj, "Reason"),
            target_name: property_str(obj, "TargetName"),
            target_type: property_str(obj, "TargetType"),
        })
    }
}

impl FromPsObject for InvocationInfo {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = as_object(value)?;
        Some(Self {
            command_name: property_str(obj, "MyCommand"),
            script_name: property_str(obj, "ScriptName"),
            line_number: property_i32(obj, "ScriptLineNumber"),
            offset_in_line: property_i32(obj, "OffsetInLine"),
            position_message: property_str(obj, "PositionMessage"),
        })
    }
}

/// A decoded `WarningRecord`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WarningRecord {
    pub message: String,
    pub invocation_info: Option<InvocationInfo>,
}

impl FromPsObject for WarningRecord {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        match value {
            PsValue::String(s) => Some(Self {
                message: s.clone(),
                invocation_info: None,
            }),
            PsValue::Object(obj) => Some(Self {
                message: property_str(obj, "Message").unwrap_or_default(),
                invocation_info: obj
                    .get("InvocationInfo")
                    .and_then(InvocationInfo::from_ps_object),
            }),
            _ => None,
        }
    }
}

/// A decoded `InformationRecord` (PowerShell 5.1+).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InformationRecord {
    pub message_data: Option<PsValue>,
    pub source: Option<String>,
    pub time_generated: Option<String>,
    pub tags: Vec<String>,
    pub user: Option<String>,
    pub computer: Option<String>,
    pub process_id: Option<i32>,
    pub native_thread_id: Option<i32>,
    pub managed_thread_id: Option<i32>,
}

impl FromPsObject for InformationRecord {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        if let PsValue::String(s) = value {
            return Some(Self {
                message_data: Some(PsValue::String(s.clone())),
                ..Self::default()
            });
        }
        let obj = as_object(value)?;
        let tags = match obj.get("Tags") {
            Some(PsValue::List(list)) => list
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        Some(Self {
            message_data: obj.get("MessageData").cloned(),
            source: property_str(obj, "Source"),
            time_generated: property_str(obj, "TimeGenerated"),
            tags,
            user: property_str(obj, "User"),
            computer: property_str(obj, "Computer"),
            process_id: property_i32(obj, "ProcessId"),
            native_thread_id: property_i32(obj, "NativeThreadId"),
            managed_thread_id: property_i32(obj, "ManagedThreadId"),
        })
    }
}

/// A decoded `ProgressRecord`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgressRecord {
    pub activity: Option<String>,
    pub activity_id: Option<i32>,
    pub status_description: Option<String>,
    pub current_operation: Option<String>,
    pub parent_activity_id: Option<i32>,
    pub percent_complete: Option<i32>,
    pub seconds_remaining: Option<i32>,
    pub record_type: Option<i32>,
}

impl FromPsObject for ProgressRecord {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = as_object(value)?;
        Some(Self {
            activity: property_str(obj, "Activity"),
            activity_id: property_i32(obj, "ActivityId"),
            status_description: property_str(obj, "StatusDescription"),
            current_operation: property_str(obj, "CurrentOperation"),
            parent_activity_id: property_i32(obj, "ParentActivityId"),
            percent_complete: property_i32(obj, "PercentComplete"),
            seconds_remaining: property_i32(obj, "SecondsRemaining"),
            record_type: property_i32(obj, "Type"),
        })
    }
}

/// A decoded `DebugRecord` / `VerboseRecord` — both share the shape of a
/// single `Message` string.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TraceRecord {
    pub message: String,
    pub invocation_info: Option<InvocationInfo>,
}

impl FromPsObject for TraceRecord {
    fn from_ps_object(value: &PsValue) -> Option<Self> {
        match value {
            PsValue::String(s) => Some(Self {
                message: s.clone(),
                invocation_info: None,
            }),
            PsValue::Object(obj) => Some(Self {
                message: property_str(obj, "Message").unwrap_or_default(),
                invocation_info: obj
                    .get("InvocationInfo")
                    .and_then(InvocationInfo::from_ps_object),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_record_from_string() {
        let v = PsValue::String("careful".into());
        let w = WarningRecord::from_ps_object(&v).unwrap();
        assert_eq!(w.message, "careful");
        assert!(w.invocation_info.is_none());
    }

    #[test]
    fn warning_record_from_object() {
        let obj = PsObject::new().with("Message", PsValue::String("careful".into()));
        let w = WarningRecord::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(w.message, "careful");
    }

    #[test]
    fn warning_record_rejects_non_object() {
        assert!(WarningRecord::from_ps_object(&PsValue::I32(7)).is_none());
    }

    #[test]
    fn error_record_decodes_minimal() {
        let obj = PsObject::new()
            .with("Exception", PsValue::String("boom".into()))
            .with(
                "FullyQualifiedErrorId",
                PsValue::String("RuntimeException".into()),
            );
        let rec = ErrorRecord::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(
            rec.fully_qualified_error_id.as_deref(),
            Some("RuntimeException")
        );
        assert_eq!(rec.exception.unwrap().message.as_deref(), Some("boom"));
    }

    #[test]
    fn error_record_decodes_rich_exception() {
        let exc = PsObject::new()
            .with("Message", PsValue::String("boom".into()))
            .with_type_names(["System.RuntimeException"]);
        let rec_obj = PsObject::new().with("Exception", PsValue::Object(exc));
        let rec = ErrorRecord::from_ps_object(&PsValue::Object(rec_obj)).unwrap();
        let exc = rec.exception.unwrap();
        assert_eq!(exc.message.as_deref(), Some("boom"));
        assert_eq!(exc.type_name.as_deref(), Some("System.RuntimeException"));
    }

    #[test]
    fn error_record_rejects_non_object() {
        assert!(ErrorRecord::from_ps_object(&PsValue::I32(1)).is_none());
    }

    #[test]
    fn information_record_from_string() {
        let rec = InformationRecord::from_ps_object(&PsValue::String("hi".into())).unwrap();
        assert!(matches!(rec.message_data, Some(PsValue::String(ref s)) if s == "hi"));
    }

    #[test]
    fn information_record_from_object_with_tags() {
        let obj = PsObject::new()
            .with("Source", PsValue::String("Test".into()))
            .with(
                "Tags",
                PsValue::List(vec![
                    PsValue::String("a".into()),
                    PsValue::String("b".into()),
                ]),
            )
            .with("ProcessId", PsValue::I32(9));
        let rec = InformationRecord::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(rec.source.as_deref(), Some("Test"));
        assert_eq!(rec.tags, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(rec.process_id, Some(9));
    }

    #[test]
    fn progress_record_decodes() {
        let obj = PsObject::new()
            .with("Activity", PsValue::String("Copying".into()))
            .with("PercentComplete", PsValue::I32(42));
        let rec = ProgressRecord::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(rec.activity.as_deref(), Some("Copying"));
        assert_eq!(rec.percent_complete, Some(42));
    }

    #[test]
    fn trace_record_decodes_both_variants() {
        let s = TraceRecord::from_ps_object(&PsValue::String("m".into())).unwrap();
        assert_eq!(s.message, "m");
        let obj = PsObject::new().with("Message", PsValue::String("n".into()));
        let o = TraceRecord::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(o.message, "n");
    }

    #[test]
    fn invocation_info_decodes() {
        let obj = PsObject::new()
            .with("MyCommand", PsValue::String("Get-Date".into()))
            .with("ScriptLineNumber", PsValue::I32(3));
        let inv = InvocationInfo::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(inv.command_name.as_deref(), Some("Get-Date"));
        assert_eq!(inv.line_number, Some(3));
    }

    #[test]
    fn category_info_decodes() {
        let obj = PsObject::new().with("Activity", PsValue::String("Do".into()));
        let cat = ErrorCategoryInfo::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(cat.activity.as_deref(), Some("Do"));
    }
}
