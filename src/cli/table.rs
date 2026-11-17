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

    let terminal_width = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width >= 60)
        .unwrap_or(100);
    let border_width = columns.saturating_mul(3).saturating_add(1);
    let available = terminal_width.saturating_sub(border_width).max(columns * 8);
    let preferred_total = preferred_widths.iter().sum::<usize>();

    let widths = if preferred_total <= available {
        preferred_widths.to_vec()
    } else {
        let minimum_total = columns * 8;
        let distributable = available.saturating_sub(minimum_total);
        let excess = preferred_total.saturating_sub(minimum_total).max(1);
        preferred_widths
            .iter()
            .map(|width| 8 + width.saturating_sub(8).saturating_mul(distributable) / excess)
            .collect::<Vec<_>>()
    };

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
