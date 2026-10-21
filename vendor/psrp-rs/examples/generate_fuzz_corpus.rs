//! Generate the **seed corpus** for `cargo fuzz`. Run with:
//!
//! ```bash
//! cargo run --example generate_fuzz_corpus
//! ```
//!
//! Seeds are written to `fuzz/seeds/<target>/` and are **checked into
//! git**. `fuzz/corpus/` is libFuzzer's own working directory (grown by
//! every run, ignored by git); `fuzz/run.sh` copies the seeds in before
//! it starts so a fresh clone fuzzes from a useful starting point
//! instead of from `""`.
//!
//! Wherever possible a seed is built with the crate's own encoders, so
//! the bytes stay in sync with the wire format automatically. The
//! hand-written CLIXML documents are copies of what a real PowerShell
//! host emits.

use std::fs;
use std::path::PathBuf;

use psrp_rs::clixml::{PsObject, PsValue, to_clixml};
use psrp_rs::fragment::{Fragment, MAX_FRAGMENT_PAYLOAD, encode_message, split_message};
use psrp_rs::message::{Destination, MessageType, PsrpMessage};

fn write(target: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("fuzz");
    path.push("seeds");
    path.push(target);
    fs::create_dir_all(&path)?;
    path.push(name);
    fs::write(&path, bytes)?;
    println!("{:>6} bytes -> fuzz/seeds/{target}/{name}", bytes.len());
    Ok(())
}

/// A client-bound PSRP message, already fragment-framed.
fn framed(object_id: u64, mt: MessageType, body: &str) -> Vec<u8> {
    let msg = PsrpMessage {
        destination: Destination::Client,
        message_type: mt,
        rpid: uuid::Uuid::nil(),
        pid: uuid::Uuid::nil(),
        data: body.to_string(),
    };
    encode_message(object_id, &msg.encode())
}

// ---------------------------------------------------------------------
// Realistic CLIXML bodies, as emitted by a live Windows PowerShell host.
// ---------------------------------------------------------------------

const SESSION_CAPABILITY: &str = r#"<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>"#;

const RUNSPACE_STATE_OPENED: &str =
    r#"<Obj RefId="0"><MS><I32 N="RunspaceState">2</I32></MS></Obj>"#;

const PIPELINE_STATE_COMPLETED: &str =
    r#"<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>"#;

const ERROR_RECORD: &str = r#"<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.ErrorRecord</T><T>System.Object</T></TN><ToString>boom</ToString><MS><Obj N="Exception" RefId="1"><TN RefId="1"><T>System.Exception</T></TN><ToString>boom</ToString><MS><S N="Message">boom</S><Nil N="InnerException"/></MS></Obj><Nil N="TargetObject"/><S N="FullyQualifiedErrorId">Microsoft.PowerShell.Commands.WriteErrorException</S><Obj N="InvocationInfo" RefId="2"><MS><S N="MyCommand">Write-Error</S><I32 N="ScriptLineNumber">1</I32><S N="Line">Write-Error boom</S></MS></Obj><Obj N="CategoryInfo" RefId="3"><MS><I32 N="Category">7</I32><S N="Reason">WriteErrorException</S><S N="TargetName"></S></MS></Obj></MS></Obj>"#;

const PROGRESS_RECORD: &str = r#"<Obj RefId="0"><MS><I64 N="SourceId">1</I64><Obj N="Record" RefId="1"><MS><S N="Activity">Copying</S><I32 N="ActivityId">0</I32><S N="StatusDescription">42%</S><I32 N="PercentComplete">42</I32><I32 N="SecondsRemaining">-1</I32><I32 N="RecordType">0</I32></MS></Obj></MS></Obj>"#;

const INFORMATION_RECORD: &str = r#"<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.InformationRecord</T></TN><MS><S N="MessageData">hello</S><S N="Source">Write-Host</S><Obj N="Tags" RefId="1"><LST><S>PSHOST</S></LST></Obj><DT N="TimeGenerated">2026-01-01T00:00:00.0000000+00:00</DT></MS></Obj>"#;

const COMMAND_METADATA: &str = r#"<Obj RefId="0"><MS><S N="Name">Get-Process</S><I32 N="CommandType">8</I32><S N="Namespace">Microsoft.PowerShell.Management</S><Obj N="Parameters" RefId="1"><DCT><En><S N="Key">Name</S><Obj N="Value" RefId="2"><MS><S N="Name">Name</S><S N="ParameterType">System.String[]</S><B N="IsMandatory">false</B><I32 N="Position">0</I32></MS></Obj></En></DCT></Obj></MS></Obj>"#;

const HOST_CALL_WRITE_LINE: &str = r#"<Obj RefId="0"><MS><I64 N="ci">1</I64><Obj N="mi" RefId="1"><TN RefId="0"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T><T>System.Enum</T></TN><ToString>WriteLine2</ToString><I32>16</I32></Obj><Obj N="mp" RefId="2"><LST><S>hello from the host</S></LST></Obj></MS></Obj>"#;

/// Every CLIXML body above, plus a few pathological but legal shapes.
fn clixml_seeds() -> Vec<(&'static str, String)> {
    let extended = to_clixml(&PsValue::Object(
        PsObject::new()
            .with("Created", PsValue::DateTime("2026-01-01T00:00:00".into()))
            .with("Bytes", PsValue::Bytes(vec![1, 2, 3]))
            .with("Id", PsValue::Guid(uuid::Uuid::nil()))
            .with("Ratio", PsValue::Double(f64::NAN))
            .with("Ch", PsValue::Char('é')),
    ));
    let nested = to_clixml(&PsValue::List(vec![
        PsValue::List(vec![PsValue::I32(1), PsValue::Null]),
        PsValue::Dict(vec![(
            PsValue::String("k".into()),
            PsValue::List(vec![PsValue::Bool(true)]),
        )]),
    ]));

    vec![
        ("session_capability.xml", SESSION_CAPABILITY.into()),
        ("runspace_state.xml", RUNSPACE_STATE_OPENED.into()),
        ("pipeline_state.xml", PIPELINE_STATE_COMPLETED.into()),
        ("error_record.xml", ERROR_RECORD.into()),
        ("progress_record.xml", PROGRESS_RECORD.into()),
        ("information_record.xml", INFORMATION_RECORD.into()),
        ("command_metadata.xml", COMMAND_METADATA.into()),
        ("host_call.xml", HOST_CALL_WRITE_LINE.into()),
        ("extended_types.xml", extended),
        ("nested_containers.xml", nested),
        ("primitive.xml", "<I32>42</I32>".into()),
        (
            "ref.xml",
            r#"<Obj RefId="abc"><MS><S N="k">v</S></MS></Obj><Ref RefId="abc"/>"#.into(),
        ),
        (
            "tnref.xml",
            r#"<Obj RefId="0"><TN RefId="7"><T>A</T><T>B</T></TN></Obj><Obj RefId="1"><TNRef RefId="7"/></Obj>"#
                .into(),
        ),
        (
            "escapes.xml",
            r"<S>_x000A_&lt;tag&gt; &amp; <![CDATA[raw]]></S>".into(),
        ),
        ("bom.xml", "\u{feff}<S>bom</S>".into()),
        ("empty_string.xml", "<S></S><S/>".into()),
    ]
}

/// Fixed runspace-pool / pipeline ids used by the message seeds.
const RPID: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const PID: [u8; 16] = [
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn main() -> std::io::Result<()> {
    // ----- clixml_decoder / records_decode / metadata_decode ----------
    // All three take raw UTF-8 CLIXML, so they share a corpus.
    for (name, body) in clixml_seeds() {
        for target in ["clixml_decoder", "records_decode", "metadata_decode"] {
            write(target, name, body.as_bytes())?;
        }
    }

    // ----- fragment_reassembler --------------------------------------
    // NOTE: this target reads the **first byte** as the delivery chunk
    // size and treats the rest as the fragment stream, so every seed
    // carries a leading size byte.
    let frag_seed = |name: &str, chunk: u8, body: &[u8]| -> std::io::Result<()> {
        let mut buf = vec![chunk];
        buf.extend_from_slice(body);
        write("fragment_reassembler", name, &buf)
    };

    let empty = Fragment {
        object_id: 1,
        fragment_id: 0,
        start: true,
        end: true,
        blob: Vec::new(),
    }
    .encode();
    frag_seed("empty.bin", 0xFF, &empty)?;
    frag_seed("single.bin", 0xFF, &encode_message(2, b"hello world"))?;
    frag_seed("byte_at_a_time.bin", 1, &encode_message(3, b"dribble"))?;

    // Two interleaved object ids, one of them split across fragments.
    let a_payload = vec![0xAA; MAX_FRAGMENT_PAYLOAD + 5];
    let b_payload = b"beta".to_vec();
    let a_frags = split_message(100, &a_payload);
    let b_frags = split_message(200, &b_payload);
    let mut interleaved = Vec::new();
    interleaved.extend(a_frags[0].encode());
    interleaved.extend(b_frags[0].encode());
    interleaved.extend(a_frags[1].encode());
    frag_seed("interleaved.bin", 0xFF, &interleaved)?;

    // Exactly on the split boundary — the arithmetic most likely to be
    // off by one.
    let boundary = vec![0x5A; MAX_FRAGMENT_PAYLOAD];
    frag_seed("boundary.bin", 0xFF, &encode_message(7, &boundary))?;

    // ----- message_decode --------------------------------------------
    for (name, mt, body) in [
        (
            "session_capability.bin",
            MessageType::SessionCapability,
            SESSION_CAPABILITY,
        ),
        (
            "runspace_state.bin",
            MessageType::RunspacePoolState,
            RUNSPACE_STATE_OPENED,
        ),
        (
            "pipeline_output.bin",
            MessageType::PipelineOutput,
            "<I32>1</I32>",
        ),
        ("error_record.bin", MessageType::ErrorRecord, ERROR_RECORD),
        (
            "host_call.bin",
            MessageType::RunspacePoolHostCall,
            HOST_CALL_WRITE_LINE,
        ),
    ] {
        let msg = PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            // Fixed, not `new_v4()`: CI regenerates the seeds and
            // asserts `git diff --exit-code`, so the output has to be
            // byte-for-byte reproducible.
            rpid: uuid::Uuid::from_bytes(RPID),
            pid: uuid::Uuid::from_bytes(PID),
            data: body.to_string(),
        };
        write("message_decode", name, &msg.encode())?;
    }
    let minimal = PsrpMessage {
        destination: Destination::Server,
        message_type: MessageType::SessionCapability,
        rpid: uuid::Uuid::nil(),
        pid: uuid::Uuid::nil(),
        data: String::new(),
    }
    .encode();
    write("message_decode", "minimal.bin", &minimal)?;

    // ----- psrp_stream / pool_receive --------------------------------
    // A whole plausible server-side conversation in one blob.
    let mut conversation = Vec::new();
    conversation.extend(framed(
        1,
        MessageType::SessionCapability,
        SESSION_CAPABILITY,
    ));
    conversation.extend(framed(
        2,
        MessageType::RunspacePoolState,
        RUNSPACE_STATE_OPENED,
    ));
    conversation.extend(framed(3, MessageType::PipelineOutput, "<S>hello</S>"));
    conversation.extend(framed(4, MessageType::ErrorRecord, ERROR_RECORD));
    conversation.extend(framed(5, MessageType::ProgressRecord, PROGRESS_RECORD));
    conversation.extend(framed(
        6,
        MessageType::InformationRecord,
        INFORMATION_RECORD,
    ));
    conversation.extend(framed(
        7,
        MessageType::PipelineState,
        PIPELINE_STATE_COMPLETED,
    ));
    write("psrp_stream", "conversation.bin", &conversation)?;
    write(
        "psrp_stream",
        "single_output.bin",
        &framed(1, MessageType::PipelineOutput, "<I32>7</I32>"),
    )?;

    // ----- known_hosts_match -----------------------------------------
    // `Arbitrary` decides the struct layout, so a seed here is just a
    // plausible byte soup containing the interesting pattern shapes.
    for (name, text) in [
        (
            "wildcards.bin",
            "*.example.com\x00!bad.example.com\x00[h]:2222\x00",
        ),
        ("stars.bin", "*a*a*a*a*b\x00aaaaaaaaaaaaaaaa\x00"),
        ("literal.bin", "example.com\x00example.com\x00"),
    ] {
        write("known_hosts_match", name, text.as_bytes())?;
    }

    println!("\nSeeds written. `fuzz/run.sh` copies them into fuzz/corpus/ before fuzzing.");
    Ok(())
}
