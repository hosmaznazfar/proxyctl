//! Shared table layout, wrapping, and separator policy for CLI output.
use tabled::settings::{
    Modify, Style, Width, object::Columns, style::HorizontalLine, themes::Theme,
};

#[derive(Clone, Copy)]
pub(super) enum Separator {
    Solid(usize),
    Dotted(usize),
}

/// Read the live width of stdout's terminal, falling back when output is redirected.
fn terminal_width() -> usize {
    use std::io::IsTerminal;

    if std::io::stdout().is_terminal() {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
            // TIOCGWINSZ only writes the winsize structure supplied above.
            let result =
                unsafe { libc::ioctl(std::io::stdout().as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
            if result == 0 && size.ws_col >= 60 {
                return usize::from(size.ws_col);
            }
        }
    }

    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width >= 60)
        .unwrap_or(100)
}

/// Apply terminal-aware wrapping and the common rounded table theme.
///
/// The width budget reserves space for borders, cell padding, and a small
/// terminal-rendering margin. This is intentionally conservative so wide
/// Unicode characters and terminal implementations cannot push rows past
/// the visible edge.
pub(super) fn apply_formatting(
    table: &mut tabled::Table,
    preferred_widths: &[usize],
    separators: &[Separator],
) {
    let columns = preferred_widths.len();
    if columns == 0 {
        table.with(Style::rounded());
        return;
    }

    let terminal_width = terminal_width();
    let border_and_padding = columns.saturating_mul(4).saturating_add(2);
    let content_budget = terminal_width
        .saturating_sub(border_and_padding)
        .max(columns);

    let weights = preferred_widths
        .iter()
        .map(|width| width.saturating_sub(1).max(1))
        .collect::<Vec<_>>();
    let total_weight = weights.iter().sum::<usize>().max(1);
    let mut remaining = content_budget;
    let mut widths = Vec::with_capacity(columns);

    for (index, weight) in weights.iter().enumerate() {
        let width = if index + 1 == columns {
            remaining
        } else {
            let share = content_budget.saturating_mul(*weight) / total_weight;
            let share = share
                .max(1)
                .min(remaining.saturating_sub(columns - index - 1));
            remaining = remaining.saturating_sub(share);
            share
        };
        widths.push(width.max(1));
    }

    for (index, width) in widths.into_iter().enumerate() {
        table.with(Modify::new(Columns::new(index..=index)).with(Width::wrap(width)));
    }

    let mut theme = Theme::from_style(Style::rounded());
    for separator in separators {
        match separator {
            Separator::Solid(row) => {
                theme.insert_horizontal_line(*row, HorizontalLine::full('─', '┼', '├', '┤'));
            }
            Separator::Dotted(row) => {
                theme.insert_horizontal_line(*row, HorizontalLine::full('·', '┼', '├', '┤'));
            }
        }
    }
    table.with(theme);
}
