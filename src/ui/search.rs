//! Global search: fuzzy-match rows across every data view at once, so an
//! operator can find where a port, service, address, or log entry appears
//! without switching views by hand. Ranking reuses the palette's fuzzy scorer.

use strum::IntoEnumIterator;

use super::fuzzy;
use super::state::UiState;
use super::views::ViewId;

/// Overlay state for the global-search prompt: the query plus the selected
/// index into the current hit list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalSearchState {
    /// Current search query.
    pub query: String,
    /// Selected index into the ranked hit list.
    pub selected: usize,
}

/// One search match: which view and row it came from, plus display text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// The view the matching row belongs to.
    pub view: ViewId,
    /// Row index into `all_rows(view)` — where selection jumps on execute.
    pub row: usize,
    /// The row's text, for display in the results list.
    pub label: String,
}

/// Upper bound on results, so a broad query can't build a giant list.
const MAX_HITS: usize = 50;

/// Fuzzy-matches `query` against every row of every data view (in the current
/// zone context), best-first. An empty query returns nothing.
#[must_use]
pub fn hits(state: &UiState, query: &str) -> Vec<SearchHit> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(i32, SearchHit)> = Vec::new();
    for view in ViewId::iter() {
        for (row, cells) in state.all_rows(view).iter().enumerate() {
            let text = cells.join(" ");
            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Score against the view name too, so "zone" / "port" / "service"
            // find rows by the view they live in — not only by cell content
            // (a zone row's cells are `dmz`, `public`, … never the word "zone").
            let haystack = format!("{} {trimmed}", view.title());
            if let Some(score) = fuzzy::score(query, &haystack) {
                scored.push((
                    score,
                    SearchHit {
                        view,
                        row,
                        label: trimmed.to_owned(),
                    },
                ));
            }
        }
    }
    // Best score first; ties keep view/row order (stable sort).
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.truncate(MAX_HITS);
    scored.into_iter().map(|(_, hit)| hit).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::mock;

    fn state() -> UiState {
        let mut s = UiState::new(&Config::default(), "test".into(), false, None);
        s.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        s
    }

    #[test]
    fn empty_query_returns_no_hits() {
        assert!(hits(&state(), "   ").is_empty());
    }

    #[test]
    fn finds_a_row_in_a_view_the_operator_is_not_on() {
        // The mock's public zone opens 8080/tcp — searchable without switching
        // to the Ports view first.
        let found = hits(&state(), "8080");
        assert!(
            found.iter().any(|h| h.view == ViewId::Ports),
            "port 8080 is found in the Ports view"
        );
    }

    #[test]
    fn matches_rows_by_view_name() {
        // Typing the view name ("zone", "port", "service") must surface that
        // view's rows even though no cell contains the word.
        let s = state();
        assert!(
            hits(&s, "zone").iter().all(|h| h.view == ViewId::Zones)
                && !hits(&s, "zone").is_empty(),
            "`zone` finds Zones rows"
        );
        assert!(
            hits(&s, "port").iter().any(|h| h.view == ViewId::Ports),
            "`port` finds Ports rows"
        );
    }
}
