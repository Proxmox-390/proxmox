use crate::TermLogFormat;
use crate::style::TextStyle;

/// Output larger than this gets cut off, as cursor movements and styles can make it a lot larger
/// than the terminal output.
const MAX_TEXT_SIZE: usize = if cfg!(test) { 65536 } else { 64 * 1024 * 1024 };

/// Turns raw terminal output into text in the given format.
///
/// Follows the cursor movements within a line, like a terminal does, for example for progress
/// updates rewriting the line after a carriage return, or for backspaces. Moving the cursor to
/// another line, as full-screen dialogs do, starts a new line, which keeps their content readable
/// in the flow of the text. Removes trailing whitespace, blank lines at the start and the end, and
/// collapses runs of blank lines into one. Drops other terminal control sequences, except for the
/// colors and text styles kept in the styled format, and other control characters except tabs.
/// Output beyond 64 MiB is cut off with a note.
pub fn clean_terminal_output(raw: &str, format: TermLogFormat) -> String {
    let mut text = TextWriter::new(format, raw.len());
    let mut chars = raw.chars();

    while let Some(c) = chars.next() {
        match c {
            '\n' => text.line_feed(),
            '\r' => text.column = 0,
            '\x08' => text.column = text.column.saturating_sub(1),
            '\x1b' => match chars.next() {
                // CSI: parameter and intermediate bytes up to a final byte in 0x40..=0x7e
                Some('[') => {
                    let mut params = String::new();
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            text.control(c, &params);
                            break;
                        }
                        params.push(c);
                    }
                }
                // OSC: up to BEL or ST, i.e. ESC followed by a backslash
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' {
                            chars.next();
                            break;
                        }
                    }
                }
                // character set designation, like `ESC ( B`
                Some('(' | ')' | '*' | '+') => {
                    chars.next();
                }
                // index, next line and reverse index
                Some('D') => text.move_down(1),
                Some('E') => {
                    text.move_down(1);
                    text.column = 0;
                }
                Some('M') => text.move_up(1),
                // other two character sequences, like `ESC 7` to save the cursor position
                _ => (),
            },
            '\t' => text.put(c),
            c if c.is_control() => (),
            c => text.put(c),
        }
    }

    text.end_line(false);
    if text.cut_off {
        text.output.push_str(&format!(
            "\n[output cut off after {} MiB]\n",
            MAX_TEXT_SIZE / 1024 / 1024
        ));
    }
    text.output
}

/// Cursor movements beyond this column, which is wider than any terminal, are cut short, to limit
/// the padding they can add.
const MAX_COLUMN: usize = 1000;

/// Writes terminal output as text, line by line.
struct TextWriter {
    format: TermLogFormat,
    output: String,
    /// The line the cursor is on, with the style of each character.
    line: Vec<(char, TextStyle)>,
    column: usize,
    style: TextStyle,
    /// The row the cursor got moved to last, if any, as counted by the terminal.
    row: Option<usize>,
    /// Whether a blank line is due before the next line with content.
    blank_line: bool,
    /// Whether text got dropped because of the size limit.
    cut_off: bool,
}

impl TextWriter {
    fn new(format: TermLogFormat, capacity: usize) -> Self {
        Self {
            format,
            output: String::with_capacity(capacity),
            line: Vec::new(),
            column: 0,
            style: TextStyle::default(),
            row: None,
            blank_line: false,
            cut_off: false,
        }
    }

    /// Whether the output reached [`MAX_TEXT_SIZE`], after which nothing more gets written.
    fn full(&self) -> bool {
        self.output.len() >= MAX_TEXT_SIZE
    }

    /// Writes a character at the cursor position, replacing any there.
    fn put(&mut self, c: char) {
        if self.column < self.line.len() {
            self.line[self.column] = (c, self.style);
        } else {
            self.line.resize(self.column, (' ', TextStyle::default()));
            self.line.push((c, self.style));
        }
        self.column += 1;
    }

    fn line_feed(&mut self) {
        self.end_line(true);
        self.row = self.row.map(|row| row.saturating_add(1));
    }

    /// Moves the cursor to another row, keeping its column, which starts a new line if the current
    /// one has content. The row is `None` if it is unknown, i.e. after relative movements without a
    /// known row to start from.
    fn change_row(&mut self, row: Option<usize>) {
        if row.is_some() && row == self.row {
            return;
        }
        let column = self.column;
        if !self.line.is_empty() {
            self.end_line(true);
        }
        // the column grows with the text written on each row, so limit the padding on the next
        self.column = column.min(MAX_COLUMN);
        self.row = row;
    }

    fn move_up(&mut self, rows: usize) {
        self.change_row(self.row.map(|row| row.saturating_sub(rows).max(1)));
    }

    fn move_down(&mut self, rows: usize) {
        self.change_row(self.row.map(|row| row.saturating_add(rows)));
    }

    /// Writes the current line to the output and starts a new one.
    fn end_line(&mut self, line_break: bool) {
        while self
            .line
            .last()
            .is_some_and(|(c, _)| *c == ' ' || *c == '\t')
        {
            self.line.pop();
        }

        if self.full() {
            self.cut_off |= !self.line.is_empty();
            self.line.clear();
        } else if self.line.is_empty() {
            self.blank_line |= line_break && !self.output.is_empty();
        } else {
            if std::mem::take(&mut self.blank_line) {
                self.output.push('\n');
            }
            let mut style = TextStyle::default();
            for (c, char_style) in self.line.drain(..) {
                if self.output.len() >= MAX_TEXT_SIZE {
                    self.cut_off = true;
                    break;
                }
                if self.format == TermLogFormat::Styled && char_style != style {
                    char_style.write_sgr(&mut self.output);
                    style = char_style;
                }
                self.output.push(c);
            }
            if style != TextStyle::default() {
                TextStyle::default().write_sgr(&mut self.output);
            }
            if line_break {
                self.output.push('\n');
            }
        }
        self.column = 0;
    }

    /// Handles a CSI control sequence.
    fn control(&mut self, action: char, params: &str) {
        let mut numbers = params.split(';').map(|param| match param.parse::<usize>() {
            Ok(0) | Err(_) => 1,
            Ok(number) => number,
        });
        let mut number = || numbers.next().unwrap_or(1);

        match action {
            'm' => self.style.apply_sgr(params),
            // cursor position, starting a new line if the row changes
            'H' | 'f' => {
                self.change_row(Some(number()));
                self.column = (number() - 1).min(MAX_COLUMN);
            }
            // cursor row, column
            'd' => self.change_row(Some(number())),
            'G' => self.column = (number() - 1).min(MAX_COLUMN),
            // cursor up and down, to the start of the line for F and E
            'A' => self.move_up(number()),
            'B' => self.move_down(number()),
            'F' => {
                self.move_up(number());
                self.column = 0;
            }
            'E' => {
                self.move_down(number());
                self.column = 0;
            }
            // cursor forward and backward
            'C' => self.column = self.column.saturating_add(number()).min(MAX_COLUMN),
            'D' => self.column = self.column.saturating_sub(number()),
            // erase in line
            'K' => match params {
                "" | "0" => self.line.truncate(self.column),
                "1" => {
                    let end = self.line.len().min(self.column + 1);
                    self.line[..end].fill((' ', TextStyle::default()));
                }
                "2" => self.line.clear(),
                _ => (),
            },
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(raw: &str) -> String {
        clean_terminal_output(raw, TermLogFormat::Plain)
    }

    fn styled(raw: &str) -> String {
        clean_terminal_output(raw, TermLogFormat::Styled)
    }

    #[test]
    fn clean_output() {
        assert_eq!(plain(""), "");
        assert_eq!(plain("no newline"), "no newline");
        assert_eq!(plain("a\r\n\r\nb\n"), "a\n\nb\n");
        assert_eq!(plain("10%\r20%\rdone\r\r\n"), "done\n");
        assert_eq!(plain("\x1b[0;1;39mbold\x1b[0m\n"), "bold\n");
        assert_eq!(plain("\x1b]0;title\x07a\x1b]0;title\x1b\\b\n"), "ab\n");
        assert_eq!(plain("\x1b(Ba\x1b7b\x07c\td\n"), "abc\td\n");
    }

    #[test]
    fn cursor_movements_in_line() {
        // like a terminal, shorter updates only replace the start of the line
        assert_eq!(plain("abcdef\rxy\n"), "xycdef\n");
        assert_eq!(plain("abcdef\rxy\x1b[K\n"), "xy\n");
        assert_eq!(plain("abcdef\x1b[3D\x1b[1Kx\n"), "   xef\n");
        assert_eq!(plain("abcdef\x1b[2K\n"), "");
        // erasing a character like shells do
        assert_eq!(plain("abc\x08 \x08\n"), "ab\n");
        assert_eq!(plain("a\x1b[3Cb\x1b[2Gc\n"), "ac  b\n");
        assert_eq!(plain("a\x1b[99999999999Gb\n").len(), MAX_COLUMN + 2);
    }

    #[test]
    fn vertical_cursor_movements() {
        // each row change starts a new line, keeping the column
        assert_eq!(plain("\x1b[1;1Hfirst\x1b[1B\rsecond\n"), "first\nsecond\n");
        assert_eq!(plain("\x1b[2;1Hsecond\x1b[1A\rfirst\n"), "second\nfirst\n");
        assert_eq!(
            plain("ab\x1b[Bc\x1b[Ed\x1b[Fe\x1b[5df\n"),
            "ab\n  c\nd\ne\n f\n"
        );
        assert_eq!(plain("ab\x1bDc\x1bEd\x1bMe\n"), "ab\n  c\nd\n e\n");
        // the cursor cannot move above the top row
        assert_eq!(plain("\x1b[1;1Hab\x1b[A\rc\n"), "cb\n");
    }

    #[test]
    fn bounded_padding() {
        let rows = 4 * MAX_COLUMN;
        let output = plain(&"x\x1b[B".repeat(rows));
        assert!(output.len() <= rows * (MAX_COLUMN + 2));
    }

    #[test]
    fn bounded_text() {
        // the limit is in bytes, also for characters taking more than one
        let raw = "\u{1f600}".repeat(100) + "\x1b[1000Gx\n";
        let output = plain(&raw.repeat(MAX_TEXT_SIZE / 1400 + 10));
        assert!(output.len() < MAX_TEXT_SIZE + 2000);
        assert!(output.ends_with(" MiB]\n"));

        // reaching the limit without dropping anything does not add a note
        let raw = ("x".repeat(1023) + "\n").repeat(MAX_TEXT_SIZE / 1024);
        assert_eq!(plain(&format!("{raw} \n\n")), raw);
        assert!(plain(&format!("{raw}\x1b[1Ay\n")).ends_with(" MiB]\n"));
        assert!(plain(&format!("{raw}y")).ends_with(" MiB]\n"));
        assert_eq!(plain(&format!("{raw}\x1b[0m\x07\n\x1b[1m \n")), raw);
        assert!(plain(&format!("{raw}\u{a0}\n")).ends_with(" MiB]\n"));

        // padding and styles count too, also within a line
        let output = plain(&"x\x1b[999C.\n".repeat(MAX_TEXT_SIZE / 1000 + 10));
        assert!(output.len() < MAX_TEXT_SIZE + 100);
        assert!(output.ends_with(" MiB]\n"));
        let raw = "\x1b[1;3;4;9;38;5;123;48;5;200m".to_string()
            + &"a\x1b[22mb\x1b[1m".repeat(MAX_TEXT_SIZE);
        let output = styled(&raw);
        assert!(output.len() < MAX_TEXT_SIZE + 100);
        assert!(output.ends_with(" MiB]\n"));
    }

    #[test]
    fn blank_lines() {
        assert_eq!(plain("\n \r\na \n\n\t\n\nb\n\n\n"), "a\n\nb\n");
    }

    #[test]
    fn full_screen_dialog() {
        let raw = concat!(
            "before\r\n",
            "\x1b[?1049h\x1b[1;24r\x1b[H\x1b[J\x1b[1;1H\x1b[97m\x1b[44m          ",
            "\x1b[2;1H          \x1b[3;3H\x1b[37m\x1b[40m\u{250c}\u{2500}\u{2510}",
            "\x1b[4;3H\u{2514}\u{2500}\u{2518}\x1b[4;10Hx\x1b[?1049l\r\n",
            "after\r\n",
        );
        assert_eq!(
            plain(raw),
            "before\n\n  \u{250c}\u{2500}\u{2510}\n  \u{2514}\u{2500}\u{2518}    x\nafter\n",
        );
    }

    #[test]
    fn styled_output() {
        assert_eq!(
            styled("\x1b[1mdpkg:\x1b[0m \x1b[1;33mwarning:\x1b[0m downgrading\r\n"),
            "\x1b[0;1mdpkg:\x1b[0m \x1b[0;1;33mwarning:\x1b[0m downgrading\n",
        );
        assert_eq!(
            styled("\x1b[31mred\nstill red\x1b[m\nplain\n"),
            "\x1b[0;31mred\x1b[0m\n\x1b[0;31mstill red\x1b[0m\nplain\n",
        );
        // styles of characters that got replaced or trimmed do not matter
        assert_eq!(styled("\x1b[44m   \x1b[0m\n"), "");
        assert_eq!(styled("\x1b[32m10%\r\x1b[0m100%\n"), "100%\n");
        assert_eq!(
            styled("\x1b[1;97;41mdialog\x1b[0m\n"),
            "\x1b[0;1mdialog\x1b[0m\n"
        );
    }
}
