//! Basic text styles of terminal output.

/// Foreground color of terminal output, limited to the basic colors that stay readable on both
/// light and dark backgrounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextColor {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
}

impl TextColor {
    const ALL: [TextColor; 6] = [
        TextColor::Red,
        TextColor::Green,
        TextColor::Yellow,
        TextColor::Blue,
        TextColor::Magenta,
        TextColor::Cyan,
    ];

    /// Returns the color for an SGR foreground color offset, i.e. 0 for black to 7 for white.
    fn from_offset(offset: u32) -> Option<Self> {
        Self::ALL.get(offset.checked_sub(1)? as usize).copied()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn offset(self) -> u32 {
        self as u32 + 1
    }
}

/// Style of a piece of terminal output, as far as kept for showing the output in web UIs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TextStyle {
    pub bold: bool,
    pub dim: bool,
    pub color: Option<TextColor>,
}

impl TextStyle {
    /// Applies the parameters of an SGR (select graphic rendition) escape sequence.
    ///
    /// Black, white and extended colors count as the default color, as they are only readable on
    /// some backgrounds. Bright colors count as the basic ones. Other parameters, like background
    /// colors, are ignored.
    pub(crate) fn apply_sgr(&mut self, params: &str) {
        let mut params = params.split(';');

        while let Some(param) = params.next() {
            // sub-parameters, like in `38:5:208`, belong to the parameter before them
            let (param, sub_params) = param.split_once(':').unwrap_or((param, ""));
            match param.parse::<u32>().unwrap_or(0) {
                0 => *self = Self::default(),
                1 => self.bold = true,
                2 => self.dim = true,
                22 => (self.bold, self.dim) = (false, false),
                code @ (30..=37 | 90..=97) => self.color = TextColor::from_offset(code % 10),
                // extended colors of text, background and underline, by palette index or as RGB
                // values
                code @ (38 | 48 | 58) => {
                    if sub_params.is_empty() {
                        let skip = match params.next() {
                            Some("5") => 1,
                            Some("2") => 3,
                            _ => 0,
                        };
                        params.by_ref().take(skip).for_each(drop);
                    }
                    if code == 38 {
                        self.color = None;
                    }
                }
                39 => self.color = None,
                _ => (),
            }
        }
    }

    /// Writes the SGR escape sequence setting this style, starting with a reset.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn write_sgr(&self, output: &mut String) {
        output.push_str("\x1b[0");
        if self.bold {
            output.push_str(";1");
        }
        if self.dim {
            output.push_str(";2");
        }
        if let Some(color) = self.color {
            output.push_str(&format!(";3{}", color.offset()));
        }
        output.push('m');
    }
}

/// Splits styled terminal output, see [`TermLogFormat::Styled`](crate::TermLogFormat), into text
/// with its style.
///
/// SGR escape sequences set the style of the text after them, starting with the default style.
/// Other escape sequences are not expected and get dropped.
pub fn styled_segments(text: &str) -> StyledSegments<'_> {
    StyledSegments {
        rest: text,
        style: TextStyle::default(),
    }
}

/// Iterator over styled terminal output, see [`styled_segments`].
pub struct StyledSegments<'a> {
    rest: &'a str,
    style: TextStyle,
}

impl<'a> Iterator for StyledSegments<'a> {
    type Item = (TextStyle, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.rest.is_empty() {
                return None;
            }
            if let Some(sequence) = self.rest.strip_prefix('\x1b') {
                // CSI parameter and intermediate bytes, up to a final byte in 0x40..=0x7e
                let sequence = sequence.strip_prefix('[').unwrap_or(sequence);
                let end = sequence
                    .find(|c: char| ('\x40'..='\x7e').contains(&c))
                    .unwrap_or(sequence.len());
                if sequence[end..].starts_with('m') {
                    self.style.apply_sgr(&sequence[..end]);
                }
                self.rest = sequence.get(end + 1..).unwrap_or_default();
                continue;
            }
            let end = self.rest.find('\x1b').unwrap_or(self.rest.len());
            let (text, rest) = self.rest.split_at(end);
            self.rest = rest;
            return Some((self.style, text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn style(params: &str) -> TextStyle {
        let mut style = TextStyle::default();
        style.apply_sgr(params);
        style
    }

    #[test]
    fn apply_sgr() {
        let bold_red = TextStyle {
            bold: true,
            dim: false,
            color: Some(TextColor::Red),
        };
        assert_eq!(style(""), TextStyle::default());
        assert_eq!(style("1;31"), bold_red);
        assert_eq!(style("0;1;91"), bold_red);
        assert_eq!(style("1;31;0"), TextStyle::default());
        assert_eq!(style("1;31;22").color, Some(TextColor::Red));
        assert_eq!(style("1;31;22;39"), TextStyle::default());
        assert_eq!(style("2;36").color, Some(TextColor::Cyan));
        assert!(style("2;36").dim);
        // not readable on every background, and backgrounds are dropped altogether
        assert_eq!(style("97;44"), TextStyle::default());
        assert_eq!(style("31;30"), TextStyle::default());
        // the parameters of extended colors are no styles of their own
        assert_eq!(style("38;5;1"), TextStyle::default());
        assert_eq!(style("48;2;1;2;3;33").color, Some(TextColor::Yellow));
        assert_eq!(style("58;5;1"), TextStyle::default());
        assert_eq!(style("31;58;2;1;2;3").color, Some(TextColor::Red));
        assert_eq!(
            style("38:5:1;1"),
            TextStyle {
                bold: true,
                ..Default::default()
            }
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn write_sgr() {
        let mut output = String::new();
        style("1;2;35").write_sgr(&mut output);
        TextStyle::default().write_sgr(&mut output);
        assert_eq!(output, "\x1b[0;1;2;35m\x1b[0m");
    }

    #[test]
    fn split_styled_text() {
        let segments: Vec<_> = styled_segments("a\x1b[0;1;33mb\x1b[0m\x1b[Kc\x1b[0;31m").collect();
        assert_eq!(
            segments,
            [
                (TextStyle::default(), "a"),
                (style("1;33"), "b"),
                (TextStyle::default(), "c"),
            ]
        );
        assert_eq!(styled_segments("").count(), 0);
        assert_eq!(styled_segments("\x1b[0;1").count(), 0);
    }
}
