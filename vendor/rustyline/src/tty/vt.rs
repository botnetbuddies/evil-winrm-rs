//! VT key decoding shared by the Windows reader and its portable unit tests.
use crate::keys::{KeyCode as K, KeyEvent, Modifiers as M};

pub(super) fn csi(sequence: &str) -> KeyEvent {
    let unknown = KeyEvent(K::UnknownEscSeq, M::NONE);
    let Some(final_byte) = sequence.chars().last() else {
        return unknown;
    };
    let arguments = &sequence[..sequence.len() - final_byte.len_utf8()];
    let parameters: Option<Vec<u16>> = if arguments.is_empty() {
        Some(Vec::new())
    } else {
        arguments
            .split(';')
            .map(|value| value.parse().ok())
            .collect()
    };
    let Some(parameters) = parameters else {
        return unknown;
    };
    let modifier = parameters.get(1).copied().unwrap_or(1);
    if !(1..=8).contains(&modifier) {
        return unknown;
    }
    let mut modifiers = M::NONE;
    if (modifier - 1) & 1 != 0 {
        modifiers |= M::SHIFT;
    }
    if (modifier - 1) & 2 != 0 {
        modifiers |= M::ALT;
    }
    if (modifier - 1) & 4 != 0 {
        modifiers |= M::CTRL;
    }
    let key = match final_byte {
        'A' => K::Up,
        'B' => K::Down,
        'C' => K::Right,
        'D' => K::Left,
        'H' => K::Home,
        'F' => K::End,
        'Z' => K::BackTab,
        'P' => K::F(1),
        'Q' => K::F(2),
        'R' => K::F(3),
        'S' => K::F(4),
        '~' => match parameters.first().copied().unwrap_or(0) {
            1 | 7 => K::Home,
            2 => K::Insert,
            3 => K::Delete,
            4 | 8 => K::End,
            5 => K::PageUp,
            6 => K::PageDown,
            11..=15 => K::F((parameters[0] - 10) as u8),
            17..=21 => K::F((parameters[0] - 11) as u8),
            23..=24 => K::F((parameters[0] - 12) as u8),
            200 => K::BracketedPasteStart,
            201 => K::BracketedPasteEnd,
            _ => return unknown,
        },
        _ => return unknown,
    };
    KeyEvent(key, modifiers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_vt_keys_and_paste_boundaries() {
        for (text, expected) in [
            ("1;6D", KeyEvent(K::Left, M::CTRL_SHIFT)),
            ("3;5~", KeyEvent(K::Delete, M::CTRL)),
            ("1;2H", KeyEvent(K::Home, M::SHIFT)),
            ("200~", KeyEvent(K::BracketedPasteStart, M::NONE)),
            ("201~", KeyEvent(K::BracketedPasteEnd, M::NONE)),
            ("Z", KeyEvent(K::BackTab, M::NONE)),
        ] {
            assert_eq!(csi(text), expected);
        }
        for text in ["", "?2004h", "1;0D", "1;9C", "999~"] {
            assert_eq!(csi(text), KeyEvent(K::UnknownEscSeq, M::NONE));
        }
    }
}
