//! Case-insensitive subsequence matcher for the command palette.
// ~40 lines instead of a fuzzy-matching dependency — the palette has
// a few dozen entries; swap in `nucleo` only if the corpus ever grows real.

/// Scores `candidate` against `query`. `None` = no match. Higher is better:
/// consecutive matches and word-boundary hits score up, late starts score down.
#[must_use]
pub fn score(query: &str, candidate: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let candidate_chars: Vec<char> = candidate.chars().flat_map(char::to_lowercase).collect();
    let mut total: i32 = 0;
    let mut position = 0usize;
    let mut previous_hit: Option<usize> = None;

    for query_char in query.chars().flat_map(char::to_lowercase) {
        let found = candidate_chars[position..]
            .iter()
            .position(|&c| c == query_char)?;
        let index = position + found;

        total += 1;
        if previous_hit == Some(index.wrapping_sub(1)) {
            total += 2; // consecutive run
        }
        let at_word_start = index == 0
            || candidate_chars
                .get(index - 1)
                .is_some_and(|c| !c.is_alphanumeric());
        if at_word_start {
            total += 3;
        }

        previous_hit = Some(index);
        position = index + 1;
    }

    // Earlier overall match beats a late one; cheap tiebreaker.
    let start_penalty = i32::try_from(previous_hit.unwrap_or(0)).unwrap_or(i32::MAX) / 8;
    Some(total - start_penalty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_matches_everything() {
        assert_eq!(score("", "anything"), Some(0));
    }

    #[test]
    fn subsequence_matches_case_insensitively() {
        assert!(score("adsv", "Add service").is_some());
        assert!(score("REFRESH", "Refresh now").is_some());
    }

    #[test]
    fn non_subsequence_does_not_match() {
        assert!(score("xyz", "Add service").is_none());
        assert!(score("addx", "Add service").is_none());
    }

    #[test]
    fn consecutive_and_word_starts_beat_scattered_hits() {
        let exact = score("add", "Add service").unwrap_or(i32::MIN);
        let scattered = score("add", "bAnDiteD").unwrap_or(i32::MIN);
        assert!(exact > scattered, "exact={exact} scattered={scattered}");
    }

    #[test]
    fn word_boundary_hit_ranks_second_word() {
        let boundary = score("serv", "Add service").unwrap_or(i32::MIN);
        let midword = score("serv", "Observers").unwrap_or(i32::MIN);
        assert!(boundary > midword, "boundary={boundary} midword={midword}");
    }
}
