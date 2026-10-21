//! History related commands tests
use super::assert_history;
use crate::config::EditMode;
use crate::keys::{KeyCode as K, KeyEvent as E, Modifiers as M};

#[test]
fn down_key() {
    for mode in &[EditMode::Emacs, EditMode::Vi] {
        assert_history(
            *mode,
            &["line1"],
            &[E(K::Down, M::NONE), E::ENTER],
            "",
            ("", ""),
        );
        assert_history(
            *mode,
            &["line1", "line2"],
            &[
                E(K::Up, M::NONE),
                E(K::Up, M::NONE),
                E(K::Down, M::NONE),
                E::ENTER,
            ],
            "",
            ("line2", ""),
        );
        assert_history(
            *mode,
            &["line1"],
            &[
                E::from('a'),
                E(K::Up, M::NONE),
                E(K::Down, M::NONE), // restore original line
                E::ENTER,
            ],
            "",
            ("a", ""),
        );
        assert_history(
            *mode,
            &["line1"],
            &[
                E::from('a'),
                E(K::Down, M::NONE), // noop
                E::ENTER,
            ],
            "",
            ("a", ""),
        );
    }
}

#[test]
fn up_key() {
    for mode in &[EditMode::Emacs, EditMode::Vi] {
        assert_history(*mode, &[], &[E(K::Up, M::NONE), E::ENTER], "", ("", ""));
        assert_history(
            *mode,
            &["line1"],
            &[E(K::Up, M::NONE), E::ENTER],
            "",
            ("line1", ""),
        );
        assert_history(
            *mode,
            &["line1", "line2"],
            &[E(K::Up, M::NONE), E(K::Up, M::NONE), E::ENTER],
            "",
            ("line1", ""),
        );
    }
}

#[test]
fn ctrl_r() {
    for mode in &[EditMode::Emacs, EditMode::Vi] {
        assert_history(
            *mode,
            &[],
            &[E::ctrl('R'), E::from('o'), E::ENTER],
            "",
            ("o", ""),
        );
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('o'),
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("cargo", ""),
        );
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('u'),
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("ru", "stc"),
        );
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('r'),
                E::from('u'),
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("r", "ustc"),
        );
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('r'),
                E::ctrl('R'),
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("r", "ustc"),
        );
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('r'),
                E::from('z'),         // no match
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("car", "go"),
        );
        assert_history(
            EditMode::Emacs,
            &["rustc", "cargo"],
            &[
                E::from('a'),
                E::ctrl('R'),
                E::from('r'),
                E::ctrl('G'), // abort (FIXME: doesn't work with vi mode)
                E::ENTER,
            ],
            "",
            ("a", ""),
        );
    }
}

#[test]
fn ctrl_r_with_long_prompt() {
    for mode in &[EditMode::Emacs, EditMode::Vi] {
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[E::ctrl('R'), E::from('o'), E::ENTER],
            ">>>>>>>>>>>>>>>>>>>>>>>>>>> ",
            ("cargo", ""),
        );
    }
}

#[test]
fn ctrl_s() {
    for mode in &[EditMode::Emacs, EditMode::Vi] {
        assert_history(
            *mode,
            &["rustc", "cargo"],
            &[
                E::ctrl('R'),
                E::from('r'),
                E::ctrl('R'),
                E::ctrl('S'),
                E(K::Right, M::NONE), // just to assert cursor pos
                E::ENTER,
            ],
            "",
            ("car", "go"),
        );
    }
}

#[test]
fn meta_lt() {
    assert_history(
        EditMode::Emacs,
        &[""],
        &[E::alt('<'), E::ENTER],
        "",
        ("", ""),
    );
    assert_history(
        EditMode::Emacs,
        &["rustc", "cargo"],
        &[E::alt('<'), E::ENTER],
        "",
        ("rustc", ""),
    );
}

#[test]
fn meta_gt() {
    assert_history(
        EditMode::Emacs,
        &[""],
        &[E::alt('>'), E::ENTER],
        "",
        ("", ""),
    );
    assert_history(
        EditMode::Emacs,
        &["rustc", "cargo"],
        &[E::alt('<'), E::alt('>'), E::ENTER],
        "",
        ("", ""),
    );
    assert_history(
        EditMode::Emacs,
        &["rustc", "cargo"],
        &[
            E::from('a'),
            E::alt('<'),
            E::alt('>'), // restore original line
            E::ENTER,
        ],
        "",
        ("a", ""),
    );
}

#[test]
fn forward_search_starts_from_normal_prompt() {
    assert_history(
        EditMode::Emacs,
        &["echo oldest", "echo newest"],
        &[E::ctrl('S'), E::from('e'), E::ENTER],
        "> ",
        ("", "echo oldest"),
    );
}

#[test]
fn last_argument_preserves_quoting_and_cycles_history() {
    assert_history(
        EditMode::Emacs,
        &["echo 'older value'", "echo \"héllo world\"  "],
        &[E::alt('.'), E::ENTER],
        "",
        ("\"héllo world\"", ""),
    );
    assert_history(
        EditMode::Emacs,
        &["echo 'older value'", "echo latest"],
        &[E::alt('.'), E::alt('.'), E::ENTER],
        "",
        ("'older value'", ""),
    );
}

#[test]
fn operate_and_get_next_repopulates_next_prompt() {
    use crate::history::History;
    let mut editor = super::init_editor(
        EditMode::Emacs,
        &[E(K::Up, M::NONE), E(K::Up, M::NONE), E::ctrl('O')],
    );
    editor.history.add("first").unwrap();
    editor.history.add("second").unwrap();
    assert_eq!("first", editor.readline("").unwrap());
    editor.add_history_entry("first").unwrap();
    editor.term.keys.clear();
    editor.term.keys.extend([E::ENTER]);
    assert_eq!("second", editor.readline("").unwrap());
}

#[test]
fn operate_and_get_next_survives_history_eviction() {
    use crate::history::History;
    let mut editor = super::init_editor(
        EditMode::Emacs,
        &[E(K::Up, M::NONE), E(K::Up, M::NONE), E::ctrl('O')],
    );
    editor.history.set_max_len(2).unwrap();
    editor.add_history_entry("first").unwrap();
    editor.add_history_entry("second").unwrap();
    assert_eq!("first", editor.readline("").unwrap());
    editor.add_history_entry("first").unwrap();
    editor.term.keys.clear();
    editor.term.keys.extend([E::ENTER]);
    assert_eq!("second", editor.readline("").unwrap());
}
