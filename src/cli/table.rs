//! Shared table layout, wrapping, and separator policy for CLI output.
use tabled::{
    settings::{
        Modify, Width,
        object::Columns,
        style::HorizontalLine,
        themes::Theme,
        Style,
    },
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
            let result = unsafe {
                libc::ioctl(
                    std::io::stdout().as_raw_fd(),
                    libc::TIOCGWINSZ,
                    &mut size,
                )
            };
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

/// Apply terminal-aware word wrapping and the common rounded table theme.
/// Explicit separators allow grouped reports to distinguish group and section boundaries.
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
    let border_width = columns.saturating_mul(3).saturating_add(1);
    let available = terminal_width.saturating_sub(border_width).max(columns * 8);
    let minimum_total = columns * 8;
    let distributable = available.saturating_sub(minimum_total);
    let preferred_total = preferred_widths.iter().sum::<usize>();
    let extra_weight = preferred_total.saturating_sub(minimum_total).max(1);
    let widths = preferred_widths
        .iter()
        .map(|width| {
            let base = 8;
            let share = width
                .saturating_sub(base)
                .saturating_mul(distributable)
                / extra_weight;
            base + share
        })
        .collect::<Vec<_>>();

    for (index, width) in widths.into_iter().enumerate() {
        table.with(
            Modify::new(Columns::new(index..=index)).with(Width::wrap(width)),
        );
    }

    let mut theme = Theme::from_style(Style::rounded());
    for separator in separators {
        match separator {
            Separator::Solid(row) => theme.insert_horizontal_line(
                *row,
                HorizontalLine::full('─', '┼', '├', '┤'),
            ),
            Separator::Dotted(row) => theme.insert_horizontal_line(
                *row,
                HorizontalLine::full('·', '┼', '├', '┤'),
            ),
        }
    }
    table.with(theme);
}
