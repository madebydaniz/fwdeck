use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn next_id(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(next),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test worker failures must fail the test"
)]
mod tests {
    use super::next_id;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn identities_start_at_one_and_never_wrap() {
        let counter = AtomicU64::new(0);
        assert_eq!(next_id(&counter), Some(1));
        assert_eq!(next_id(&counter), Some(2));

        let exhausted = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_id(&exhausted), Some(u64::MAX));
        assert_eq!(next_id(&exhausted), None);
        assert_eq!(next_id(&exhausted), None);
        assert_eq!(exhausted.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn concurrent_allocations_are_unique_and_gapless() {
        let counter = AtomicU64::new(0);
        let start = Barrier::new(8);
        let mut ids = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        (0..128)
                            .map(|_| next_id(&counter).expect("identity available"))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("allocation worker completed"))
                .collect::<Vec<_>>()
        });
        ids.sort_unstable();
        assert_eq!(ids, (1..=1024).collect::<Vec<_>>());
        assert_eq!(counter.load(Ordering::Relaxed), 1024);
    }
}
