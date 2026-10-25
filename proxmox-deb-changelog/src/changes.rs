/// A block of the changes of a changelog entry, see [`parse_changes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeBlock {
    /// A list item, usually marked with `*`, or with `-` or `+` when nested, with continuation
    /// lines joined.
    Item {
        text: String,
        children: Vec<ChangeBlock>,
    },
    /// Other text, with its line breaks, as it can be an example of output or configuration.
    Paragraph(String),
    /// The start of the changes of one author, like `[ Some One ]`, for entries combining the work
    /// of several people.
    Author(String),
}

/// Parses the changes of an entry, see [`ChangelogEntry::changes`](crate::ChangelogEntry), into
/// lists, sub-lists, other text and author sections, for showing them structured.
///
/// Lines are nested by the indentation of their list markers, more indented lines continue an
/// item until a blank line.
pub fn parse_changes(changes: &str) -> Vec<ChangeBlock> {
    struct Item {
        indent: usize,
        text: String,
        children: Vec<ChangeBlock>,
    }

    #[derive(Clone, Copy)]
    enum Continued {
        Item,
        Paragraph { indent: usize },
    }

    fn close(open: &mut Vec<Item>, root: &mut Vec<ChangeBlock>) {
        let Some(item) = open.pop() else {
            return;
        };
        let block = ChangeBlock::Item {
            text: item.text,
            children: item.children,
        };
        match open.last_mut() {
            Some(parent) => parent.children.push(block),
            None => root.push(block),
        }
    }

    let mut root = Vec::new();
    // the open list items, by the indentation of their marker
    let mut open: Vec<Item> = Vec::new();
    // what the next line continues, with the number of items open around it
    let mut current: Option<(Continued, usize)> = None;

    for line in changes.split('\n') {
        let content = line.trim();
        if content.is_empty() {
            current = None;
            continue;
        }
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        if let Some(name) = author_name(content).filter(|_| indent <= 2) {
            while !open.is_empty() {
                close(&mut open, &mut root);
            }
            root.push(ChangeBlock::Author(name.to_string()));
            current = None;
            continue;
        }
        while open.last().is_some_and(|item| item.indent >= indent) {
            close(&mut open, &mut root);
        }
        let depth = open.len();
        if let Some(text) = bullet_text(content) {
            open.push(Item {
                indent,
                text: text.to_string(),
                children: Vec::new(),
            });
            current = Some((Continued::Item, depth + 1));
            continue;
        }

        if let Some((Continued::Item, open_items)) = current
            && open_items == depth
            && let Some(item) = open.last_mut()
        {
            item.text.push(' ');
            item.text.push_str(content);
            continue;
        }
        let blocks = match open.last_mut() {
            Some(item) => &mut item.children,
            None => &mut root,
        };
        if let Some((Continued::Paragraph { indent: start }, open_items)) = current
            && open_items == depth
            && indent >= start
            && let Some(ChangeBlock::Paragraph(text)) = blocks.last_mut()
        {
            let rest: String = line.chars().skip(start).collect();
            text.push('\n');
            text.push_str(rest.trim_end());
        } else {
            blocks.push(ChangeBlock::Paragraph(content.to_string()));
            current = Some((Continued::Paragraph { indent }, depth));
        }
    }
    while !open.is_empty() {
        close(&mut open, &mut root);
    }
    root
}

/// The text of a list item, after a `*`, `-` or `+` marker and whitespace.
fn bullet_text(content: &str) -> Option<&str> {
    let rest = content.strip_prefix(['*', '+', '-'])?;
    let text = rest.trim_start();
    (text.len() < rest.len() && !text.is_empty()).then_some(text)
}

/// The name in an author line like `[ Some One ]`.
fn author_name(content: &str) -> Option<&str> {
    let name = content.strip_prefix('[')?.strip_suffix(']')?.trim();
    (!name.is_empty() && !name.contains(']')).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(text: &str, children: Vec<ChangeBlock>) -> ChangeBlock {
        ChangeBlock::Item {
            text: text.to_string(),
            children,
        }
    }

    #[test]
    fn parse_lists() {
        let changes = "  [ Alice ]
  * fix #1234: something long that wraps
    onto a second line. Closes: #98765
    - sub item one
      continued
    - sub item two
  * CVE-2026-12345: buffer overflow <script>

  [ Bob ]
  * another change
    with an example:

      $ some command
        output
Plain trailing paragraph";
        assert_eq!(
            parse_changes(changes),
            [
                ChangeBlock::Author("Alice".into()),
                item(
                    "fix #1234: something long that wraps onto a second line. Closes: #98765",
                    vec![
                        item("sub item one continued", vec![]),
                        item("sub item two", vec![]),
                    ],
                ),
                item("CVE-2026-12345: buffer overflow <script>", vec![]),
                ChangeBlock::Author("Bob".into()),
                item(
                    "another change with an example:",
                    vec![ChangeBlock::Paragraph("$ some command\n  output".into())],
                ),
                ChangeBlock::Paragraph("Plain trailing paragraph".into()),
            ]
        );
    }

    #[test]
    fn parse_paragraphs() {
        // text continued by more indented lines, and numbered lists, keep their line breaks
        assert_eq!(
            parse_changes("  New upstream release:\n    1. one\n    2. two\n"),
            [ChangeBlock::Paragraph(
                "New upstream release:\n  1. one\n  2. two".into()
            )]
        );
        // bracketed text that is indented further is no author
        assert_eq!(
            parse_changes("  * config:\n\n      [section]\n      key = value\n"),
            [item(
                "config:",
                vec![ChangeBlock::Paragraph("[section]\nkey = value".into())]
            )]
        );
        assert_eq!(parse_changes(""), []);
        assert_eq!(parse_changes("\n  \n"), []);
    }
}
