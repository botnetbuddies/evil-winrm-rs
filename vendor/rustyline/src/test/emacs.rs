use super::{assert_line, assert_line_with_initial};
// Emacs specific key bindings
use super::{assert_cursor, assert_history};
use crate::config::EditMode;
use crate::keys::{KeyCode as K, KeyEvent as E, Modifiers as M};

#[test]
fn ctrl_a() {
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::ctrl('A'), E::ENTER],
        ("", "Hi"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("test test\n123", "foo"),
        &[E::ctrl('A'), E::ENTER],
        ("test test\n", "123foo"),
    );
}

#[test]
fn ctrl_e() {
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::ctrl('E'), E::ENTER],
        ("Hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("foo", "test test\n123"),
        &[E::ctrl('E'), E::ENTER],
        ("footest test", "\n123"),
    );
}

#[test]
fn ctrl_b() {
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::ctrl('B'), E::ENTER],
        ("H", "i"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::alt('2'), E::ctrl('B'), E::ENTER],
        ("", "Hi"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::alt('-'), E::alt('2'), E::ctrl('B'), E::ENTER],
        ("Hi", ""),
    );
}

#[test]
fn ctrl_f() {
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::ctrl('F'), E::ENTER],
        ("H", "i"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::alt('2'), E::ctrl('F'), E::ENTER],
        ("Hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::alt('-'), E::alt('2'), E::ctrl('F'), E::ENTER],
        ("", "Hi"),
    );
}

#[test]
fn ctrl_h() {
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::ctrl('H'), E::ENTER],
        ("H", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::alt('2'), E::ctrl('H'), E::ENTER],
        ("", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::alt('-'), E::alt('2'), E::ctrl('H'), E::ENTER],
        ("", ""),
    );
}

#[test]
fn backspace() {
    assert_cursor(
        EditMode::Emacs,
        ("", ""),
        &[E::BACKSPACE, E::ENTER],
        ("", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::BACKSPACE, E::ENTER],
        ("H", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::BACKSPACE, E::ENTER],
        ("", "Hi"),
    );
}

#[test]
fn ctrl_k() {
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::ctrl('K'), E::ENTER],
        ("Hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::ctrl('K'), E::ENTER],
        ("", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("B", "ye"),
        &[E::ctrl('K'), E::ENTER],
        ("B", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", "foo\nbar"),
        &[E::ctrl('K'), E::ENTER],
        ("Hi", "\nbar"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", "\nbar"),
        &[E::ctrl('K'), E::ENTER],
        ("Hi", "bar"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", "bar"),
        &[E::ctrl('K'), E::ENTER],
        ("Hi", ""),
    );
}

#[test]
fn ctrl_u() {
    assert_cursor(
        EditMode::Emacs,
        ("", "Hi"),
        &[E::ctrl('U'), E::ENTER],
        ("", "Hi"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::ctrl('U'), E::ENTER],
        ("", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("B", "ye"),
        &[E::ctrl('U'), E::ENTER],
        ("", "ye"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("foo\nbar", "Hi"),
        &[E::ctrl('U'), E::ENTER],
        ("foo\n", "Hi"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("foo\n", "Hi"),
        &[E::ctrl('U'), E::ENTER],
        ("foo", "Hi"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("foo", "Hi"),
        &[E::ctrl('U'), E::ENTER],
        ("", "Hi"),
    );
}
#[test]
fn ctrl_n() {
    assert_history(
        EditMode::Emacs,
        &["line1", "line2"],
        &[E::ctrl('P'), E::ctrl('P'), E::ctrl('N'), E::ENTER],
        "",
        ("line2", ""),
    );
}

#[test]
fn ctrl_p() {
    assert_history(
        EditMode::Emacs,
        &["line1"],
        &[E::ctrl('P'), E::ENTER],
        "",
        ("line1", ""),
    );
}

#[test]
fn ctrl_t() {
    /* FIXME
    assert_cursor(
        ("ab", "cd"),
        &[E::alt('2'), E::ctrl('T'), E::ENTER],
        ("acdb", ""),
    );*/
}

#[test]
fn ctrl_x_ctrl_u() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello, ", "world"),
        &[E::ctrl('W'), E::ctrl('X'), E::ctrl('U'), E::ENTER],
        ("Hello, ", "world"),
    );
}

#[test]
fn meta_b() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello, world!", ""),
        &[E::alt('B'), E::ENTER],
        ("Hello, ", "world!"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hello, world!", ""),
        &[E::alt('2'), E::alt('B'), E::ENTER],
        ("", "Hello, world!"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hello, world!"),
        &[E::alt('-'), E::alt('B'), E::ENTER],
        ("Hello", ", world!"),
    );
}

#[test]
fn meta_f() {
    assert_cursor(
        EditMode::Emacs,
        ("", "Hello, world!"),
        &[E::alt('F'), E::ENTER],
        ("Hello", ", world!"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "Hello, world!"),
        &[E::alt('2'), E::alt('F'), E::ENTER],
        ("Hello, world", "!"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hello, world!", ""),
        &[E::alt('-'), E::alt('F'), E::ENTER],
        ("Hello, ", "world!"),
    );
}

#[test]
fn meta_c() {
    assert_cursor(
        EditMode::Emacs,
        ("hi", ""),
        &[E::alt('C'), E::ENTER],
        ("hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "hi"),
        &[E::alt('C'), E::ENTER],
        ("Hi", ""),
    );
    /* FIXME
    assert_cursor(
        ("", "hi test"),
        &[E::alt('2'), E::alt('C'), E::ENTER],
        ("Hi Test", ""),
    );*/
}

#[test]
fn meta_l() {
    assert_cursor(
        EditMode::Emacs,
        ("Hi", ""),
        &[E::alt('L'), E::ENTER],
        ("Hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "HI"),
        &[E::alt('L'), E::ENTER],
        ("hi", ""),
    );
    /* FIXME
    assert_cursor(
        ("", "HI TEST"),
        &[E::alt('2'), E::alt('L'), E::ENTER],
        ("hi test", ""),
    );*/
}

#[test]
fn meta_u() {
    assert_cursor(
        EditMode::Emacs,
        ("hi", ""),
        &[E::alt('U'), E::ENTER],
        ("hi", ""),
    );
    assert_cursor(
        EditMode::Emacs,
        ("", "hi"),
        &[E::alt('U'), E::ENTER],
        ("HI", ""),
    );
    /* FIXME
    assert_cursor(
        ("", "hi test"),
        &[E::alt('2'), E::alt('U'), E::ENTER],
        ("HI TEST", ""),
    );*/
}

#[test]
fn meta_d() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello", ", world!"),
        &[E::alt('D'), E::ENTER],
        ("Hello", "!"),
    );
    assert_cursor(
        EditMode::Emacs,
        ("Hello", ", world!"),
        &[E::alt('2'), E::alt('D'), E::ENTER],
        ("Hello", ""),
    );
}

#[test]
fn meta_t() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello", ", world!"),
        &[E::alt('T'), E::ENTER],
        ("world, Hello", "!"),
    );
    /* FIXME
    assert_cursor(
        ("One Two", " Three Four"),
        &[E::alt('T'), E::ENTER],
        ("One Four Three Two", ""),
    );*/
}

#[test]
fn meta_y() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello, world", "!"),
        &[
            E::ctrl('W'),
            E(K::Left, M::NONE),
            E::ctrl('W'),
            E::ctrl('Y'),
            E::alt('Y'),
            E::ENTER,
        ],
        ("world", " !"),
    );
}

#[test]
fn meta_backspace() {
    assert_cursor(
        EditMode::Emacs,
        ("Hello, wor", "ld!"),
        &[E(K::Backspace, M::ALT), E::ENTER],
        ("Hello, ", "ld!"),
    );
}

#[test]
fn meta_digit() {
    assert_cursor(
        EditMode::Emacs,
        ("", ""),
        &[E::alt('3'), E::from('h'), E::ENTER],
        ("hhh", ""),
    );
}

#[test]
fn selection_copy_cut_yank_and_unicode_replacement() {
    assert_line_with_initial(
        EditMode::Emacs,
        ("hello world", ""),
        &[
            E(K::Left, M::CTRL_SHIFT),
            E::ctrl('W'),
            E::ctrl('Y'),
            E::ENTER,
        ],
        "hello world",
    );
    assert_line_with_initial(
        EditMode::Emacs,
        ("hello world", ""),
        &[
            E(K::Left, M::CTRL_SHIFT),
            E::alt('w'),
            E::ctrl('E'),
            E::ctrl('Y'),
            E::ENTER,
        ],
        "hello worldworld",
    );
    assert_line_with_initial(
        EditMode::Emacs,
        ("hé界", ""),
        &[E(K::Left, M::SHIFT), E::from('!'), E::ENTER],
        "hé!",
    );
    assert_line_with_initial(
        EditMode::Emacs,
        ("abc", ""),
        &[
            E::ctrl('@'),
            E::ctrl('A'),
            E::ctrl('W'),
            E::ctrl('Y'),
            E::ENTER,
        ],
        "abc",
    );
}

#[test]
fn selection_collapses_and_abort_clears_mark() {
    assert_line_with_initial(
        EditMode::Emacs,
        ("abc", ""),
        &[
            E(K::Left, M::SHIFT),
            E(K::Left, M::NONE),
            E::from('!'),
            E::ENTER,
        ],
        "a!bc",
    );
    assert_line_with_initial(
        EditMode::Emacs,
        ("abc", ""),
        &[
            E::ctrl('@'),
            E::ctrl('A'),
            E::ctrl('G'),
            E::from('!'),
            E::ENTER,
        ],
        "!abc",
    );
}

#[test]
fn keyboard_macro_records_and_repeats_edits() {
    assert_line_with_initial(
        EditMode::Emacs,
        ("abc", ""),
        &[
            E::ctrl('X'),
            E::from('('),
            E::BACKSPACE,
            E::from('!'),
            E::ctrl('X'),
            E::from(')'),
            E::ctrl('X'),
            E::from('e'),
            E::ENTER,
        ],
        "ab!",
    );
    assert_line(
        EditMode::Emacs,
        &[
            E::ctrl('X'),
            E::from('('),
            E::from('x'),
            E::ctrl('X'),
            E::from(')'),
            E::alt('3'),
            E::ctrl('X'),
            E::from('e'),
            E::ENTER,
        ],
        "xxxx",
    );
}

#[test]
fn keyboard_macro_persists_between_readline_calls() {
    let mut editor = super::init_editor(
        EditMode::Emacs,
        &[
            E::ctrl('X'),
            E::from('('),
            E::from('x'),
            E::ctrl('X'),
            E::from(')'),
            E::ENTER,
        ],
    );
    assert_eq!("x", editor.readline("").unwrap());
    editor
        .term
        .keys
        .extend([E::ctrl('X'), E::from('e'), E::ENTER]);
    assert_eq!("x", editor.readline("").unwrap());
}
