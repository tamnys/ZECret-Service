//! Complete, bounded scans assembled from decoded provider pages.
//!
//! These pure accumulators establish pagination consistency only. The HTTPS
//! caller retains workspace, app and time-window context separately. Completion
//! is neither an atomic provider snapshot, an identity join, nor a disk or
//! billing-finality receipt.

use crate::{
    LifecycleError,
    provider_wire::{Cvm, InventoryPage, UsagePage, UsageRow},
};
use std::{collections::BTreeSet, num::NonZeroUsize};

/// An inventory scan through its declared last page with matching unique count.
/// No public constructor or deserialization can manufacture a completed scan.
#[derive(Debug)]
pub struct InventoryScan {
    items: Vec<Cvm>,
    total: u64,
    pages: u64,
}

impl InventoryScan {
    pub fn items(&self) -> &[Cvm] {
        &self.items
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn pages(&self) -> u64 {
        self.pages
    }
}

/// A usage scan that reached an empty page, retaining each billing key once.
/// Page summaries are deliberately not retained or charged as additional usage.
#[derive(Debug)]
pub struct UsageScan {
    rows: Vec<UsageRow>,
}

impl UsageScan {
    pub fn rows(&self) -> &[UsageRow] {
        &self.rows
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Collecting,
    Complete,
    Rejected,
}

const INVALID: LifecycleError = LifecycleError("inconsistent Phala provider scan");
const INCOMPLETE: LifecycleError = LifecycleError("Phala provider scan is incomplete");
const LIMIT: LifecycleError = LifecycleError("Phala provider scan record bound exceeded");

pub(crate) struct InventoryAccumulator {
    state: State,
    page_size: u64,
    max_records: NonZeroUsize,
    next_page: u64,
    declared: Option<(u64, u64)>,
    items: Vec<Cvm>,
    seen: BTreeSet<String>,
}

impl InventoryAccumulator {
    pub(crate) fn new(page_size: u64, max_records: NonZeroUsize) -> Result<Self, LifecycleError> {
        // Pinned provider query contract, not an inferred project limit.
        if !(1..=100).contains(&page_size) {
            return Err(INVALID);
        }
        Ok(Self {
            state: State::Collecting,
            page_size,
            max_records,
            next_page: 1,
            declared: None,
            items: Vec::new(),
            seen: BTreeSet::new(),
        })
    }

    pub(crate) fn next_page(&self) -> Result<u64, LifecycleError> {
        if self.state != State::Collecting {
            return Err(INVALID);
        }
        Ok(self.next_page)
    }

    pub(crate) fn push(&mut self, page: InventoryPage) -> Result<bool, LifecycleError> {
        let result = self.accept(page);
        if result.is_err() {
            // A caller cannot discard an inconsistent page and later produce
            // a successful result from the same scan.
            self.state = State::Rejected;
        }
        result
    }

    fn accept(&mut self, page: InventoryPage) -> Result<bool, LifecycleError> {
        if self.state != State::Collecting
            || page.page != self.next_page
            || page.page_size != self.page_size
            || u64::try_from(page.items.len()).map_err(|_| INVALID)? > self.page_size
            || (page.pages == 0 && (page.page != 1 || page.total != 0 || !page.items.is_empty()))
            || (page.pages != 0 && page.page > page.pages)
            || self
                .declared
                .is_some_and(|declared| declared != (page.total, page.pages))
        {
            return Err(INVALID);
        }
        let retained = checked_retention(self.items.len(), page.items.len(), self.max_records)?;
        if u128::from(page.total) > self.max_records.get() as u128 {
            return Err(LIMIT);
        }
        if retained as u128 > u128::from(page.total) {
            return Err(INVALID);
        }
        let complete = page.pages == 0 || page.page == page.pages;
        if complete && retained as u128 != u128::from(page.total) {
            return Err(INVALID);
        }
        let mut page_ids = BTreeSet::new();
        for item in &page.items {
            if item.id.trim().is_empty()
                || self.seen.contains(&item.id)
                || !page_ids.insert(item.id.as_str())
            {
                return Err(INVALID);
            }
        }
        drop(page_ids);
        self.items
            .try_reserve(page.items.len())
            .map_err(|_| LIMIT)?;
        self.declared = Some((page.total, page.pages));
        for item in page.items {
            self.seen.insert(item.id.clone());
            self.items.push(item);
        }
        if complete {
            self.state = State::Complete;
        } else {
            self.next_page = self.next_page.checked_add(1).ok_or(INVALID)?;
        }
        Ok(complete)
    }

    pub(crate) fn finish(self) -> Result<InventoryScan, LifecycleError> {
        if self.state != State::Complete {
            return Err(INCOMPLETE);
        }
        let (total, pages) = self.declared.ok_or(INCOMPLETE)?;
        Ok(InventoryScan {
            items: self.items,
            total,
            pages,
        })
    }
}

pub(crate) struct UsageAccumulator {
    state: State,
    limit: u64,
    max_records: NonZeroUsize,
    next_offset: u64,
    rows: Vec<UsageRow>,
    seen: BTreeSet<String>,
}

impl UsageAccumulator {
    pub(crate) fn new(limit: u64, max_records: NonZeroUsize) -> Result<Self, LifecycleError> {
        // Pinned provider query contract, not an inferred project limit.
        if !(1..=5000).contains(&limit) {
            return Err(INVALID);
        }
        Ok(Self {
            state: State::Collecting,
            limit,
            max_records,
            next_offset: 0,
            rows: Vec::new(),
            seen: BTreeSet::new(),
        })
    }

    pub(crate) fn next_offset(&self) -> Result<u64, LifecycleError> {
        if self.state != State::Collecting {
            return Err(INVALID);
        }
        Ok(self.next_offset)
    }

    pub(crate) fn push(&mut self, page: UsagePage) -> Result<bool, LifecycleError> {
        let result = self.accept(page);
        if result.is_err() {
            self.state = State::Rejected;
        }
        result
    }

    fn accept(&mut self, page: UsagePage) -> Result<bool, LifecycleError> {
        if self.state != State::Collecting
            || page.total != u64::try_from(page.usage.len()).map_err(|_| INVALID)?
            || page.total > self.limit
        {
            return Err(INVALID);
        }
        checked_retention(self.rows.len(), page.usage.len(), self.max_records)?;
        let next_offset = self.next_offset.checked_add(page.total).ok_or(INVALID)?;
        let mut page_keys = BTreeSet::new();
        for row in &page.usage {
            if row.billing_key.trim().is_empty()
                || self.seen.contains(&row.billing_key)
                || !page_keys.insert(row.billing_key.as_str())
            {
                // Even an identical repeated row is not pagination progress.
                // Changed identity/category/exact amount under that key also
                // fails rather than replacing previously observed information.
                return Err(INVALID);
            }
        }
        drop(page_keys);
        self.rows.try_reserve(page.usage.len()).map_err(|_| LIMIT)?;
        let complete = page.usage.is_empty();
        for row in page.usage {
            self.seen.insert(row.billing_key.clone());
            self.rows.push(row);
        }
        self.next_offset = next_offset;
        if complete {
            self.state = State::Complete;
        }
        Ok(complete)
    }

    pub(crate) fn finish(self) -> Result<UsageScan, LifecycleError> {
        if self.state != State::Complete {
            return Err(INCOMPLETE);
        }
        Ok(UsageScan { rows: self.rows })
    }
}

fn checked_retention(
    current: usize,
    additional: usize,
    maximum: NonZeroUsize,
) -> Result<usize, LifecycleError> {
    current
        .checked_add(additional)
        .filter(|total| *total <= maximum.get())
        .ok_or(LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::ExactUsd;

    fn bound(records: usize) -> NonZeroUsize {
        NonZeroUsize::new(records).unwrap()
    }

    fn cvm(id: &str) -> Cvm {
        Cvm {
            id: id.to_owned(),
            status: "running".to_owned(),
            app_id: None,
            instance_id: None,
            vm_uuid: None,
            workspace_id: None,
            created_at: None,
            deleted_at: None,
        }
    }

    fn inventory(page: u64, total: u64, pages: u64, ids: &[&str]) -> InventoryPage {
        InventoryPage {
            items: ids.iter().map(|id| cvm(id)).collect(),
            total,
            page,
            page_size: 2,
            pages,
        }
    }

    fn row(key: &str, amount: &str) -> UsageRow {
        UsageRow {
            instance_id: "usage-instance".to_owned(),
            project_id: 1,
            team_id: 2,
            timestamp: "2026-09-25T00:00:00Z".to_owned(),
            event_type: "cvm".to_owned(),
            usage_type: "compute".to_owned(),
            billing_start: "2026-09-25T00:00:00Z".to_owned(),
            billing_end: "2026-09-25T01:00:00Z".to_owned(),
            billing_key: key.to_owned(),
            billing_hour: "2026-09-25T00".to_owned(),
            billing_day: "2026-09-25".to_owned(),
            cost: ExactUsd::parse_json_number(amount).unwrap(),
        }
    }

    fn usage(rows: Vec<UsageRow>) -> UsagePage {
        UsagePage {
            total: rows.len() as u64,
            usage: rows,
            total_cost: ExactUsd::parse_json_number("123.456").unwrap(),
        }
    }

    #[test]
    fn inventory_requires_all_declared_pages_and_preserves_optional_workspace() {
        let mut scan = InventoryAccumulator::new(2, bound(3)).unwrap();
        assert_eq!(scan.next_page().unwrap(), 1);
        assert!(!scan.push(inventory(1, 3, 2, &["a", "b"])).unwrap());
        assert_eq!(scan.next_page().unwrap(), 2);
        let mut last = inventory(2, 3, 2, &["c"]);
        last.items[0].workspace_id = Some("workspace-original".to_owned());
        assert!(scan.push(last).unwrap());
        assert!(scan.next_page().is_err());
        let result = scan.finish().unwrap();
        assert_eq!((result.total(), result.pages()), (3, 2));
        assert_eq!(result.items().len(), 3);
        assert_eq!(result.items()[0].workspace_id, None);
        assert_eq!(
            result.items()[2].workspace_id.as_deref(),
            Some("workspace-original")
        );

        let mut interrupted = InventoryAccumulator::new(2, bound(3)).unwrap();
        interrupted.push(inventory(1, 3, 2, &["a", "b"])).unwrap();
        assert!(interrupted.finish().is_err());
    }

    #[test]
    fn empty_inventory_conventions_complete_only_with_zero_total() {
        for pages in [0, 1] {
            let mut scan = InventoryAccumulator::new(2, bound(1)).unwrap();
            assert!(scan.push(inventory(1, 0, pages, &[])).unwrap());
            assert!(scan.finish().unwrap().items().is_empty());
        }
        for invalid in [
            inventory(2, 0, 0, &[]),
            inventory(1, 1, 0, &[]),
            inventory(1, 0, 0, &["a"]),
            inventory(1, 1, 1, &[]),
        ] {
            let mut scan = InventoryAccumulator::new(2, bound(1)).unwrap();
            assert!(scan.push(invalid).is_err());
            assert!(scan.finish().is_err());
        }
    }

    #[test]
    fn inventory_changes_gaps_duplicates_and_final_count_mismatch_poison_scan() {
        for invalid in [
            inventory(1, 3, 2, &["c"]),
            inventory(3, 3, 2, &["c"]),
            inventory(2, 4, 2, &["c", "d"]),
            inventory(2, 3, 3, &["c"]),
            inventory(2, 3, 2, &["a"]),
            inventory(2, 3, 2, &[]),
            inventory(2, 3, 2, &["c", "d", "e"]),
        ] {
            let mut scan = InventoryAccumulator::new(2, bound(5)).unwrap();
            scan.push(inventory(1, 3, 2, &["a", "b"])).unwrap();
            assert!(scan.push(invalid).is_err());
            assert!(scan.push(inventory(2, 3, 2, &["c"])).is_err());
            assert!(scan.finish().is_err());
        }
        let mut duplicate = InventoryAccumulator::new(2, bound(2)).unwrap();
        assert!(duplicate.push(inventory(1, 2, 1, &["a", "a"])).is_err());
        let mut wrong_size = InventoryAccumulator::new(1, bound(2)).unwrap();
        assert!(wrong_size.push(inventory(1, 2, 1, &["a", "b"])).is_err());
    }

    #[test]
    fn record_bounds_are_enforced_before_any_page_retention() {
        let mut inventory_scan = InventoryAccumulator::new(2, bound(1)).unwrap();
        assert_eq!(inventory_scan.push(inventory(1, 2, 2, &["a"])), Err(LIMIT));
        assert!(inventory_scan.items.is_empty());
        assert!(inventory_scan.seen.is_empty());

        let mut usage_scan = UsageAccumulator::new(2, bound(1)).unwrap();
        assert!(!usage_scan.push(usage(vec![row("a", "1")])).unwrap());
        assert_eq!(usage_scan.push(usage(vec![row("b", "2")])), Err(LIMIT));
        assert_eq!(usage_scan.rows.len(), 1);
        assert_eq!(usage_scan.seen.len(), 1);
        assert!(usage_scan.finish().is_err());
        assert_eq!(
            checked_retention(usize::MAX, 1, bound(usize::MAX)),
            Err(LIMIT)
        );
    }

    #[test]
    fn usage_continues_after_short_pages_and_requires_empty_termination() {
        let mut scan = UsageAccumulator::new(500, bound(2)).unwrap();
        assert_eq!(scan.next_offset().unwrap(), 0);
        assert!(!scan.push(usage(vec![row("a", "0.0000001")])).unwrap());
        assert_eq!(scan.next_offset().unwrap(), 1);
        assert!(!scan.push(usage(vec![row("b", "0.0000002")])).unwrap());
        assert_eq!(scan.next_offset().unwrap(), 2);
        assert!(scan.push(usage(vec![])).unwrap());
        assert!(scan.next_offset().is_err());
        let result = scan.finish().unwrap();
        assert_eq!(result.rows().len(), 2);
        assert_ne!(result.rows()[0].cost, result.rows()[1].cost);

        let mut interrupted = UsageAccumulator::new(500, bound(1)).unwrap();
        interrupted.push(usage(vec![row("a", "1")])).unwrap();
        assert!(interrupted.finish().is_err());
        let mut empty = UsageAccumulator::new(500, bound(1)).unwrap();
        assert!(empty.push(usage(vec![])).unwrap());
        assert!(empty.finish().unwrap().rows().is_empty());
    }

    #[test]
    fn repeated_usage_keys_fail_for_equivalent_or_conflicting_exact_costs() {
        for amount in ["1e-7", "0.00000010", "0.0000002", "1"] {
            let mut scan = UsageAccumulator::new(2, bound(2)).unwrap();
            scan.push(usage(vec![row("same", "0.0000001")])).unwrap();
            assert!(scan.push(usage(vec![row("same", amount)])).is_err());
            assert!(scan.push(usage(vec![])).is_err());
            assert!(scan.finish().is_err());
        }
        let mut same_page = UsageAccumulator::new(2, bound(2)).unwrap();
        assert!(
            same_page
                .push(usage(vec![row("same", "1"), row("same", "2")]))
                .is_err()
        );
        assert!(same_page.rows.is_empty());
    }

    #[test]
    fn usage_rejects_counts_limit_excess_and_offset_overflow() {
        let mut wrong_count = usage(vec![row("a", "1")]);
        wrong_count.total = 2;
        for invalid in [wrong_count, usage(vec![row("a", "1"), row("b", "2")])] {
            let mut scan = UsageAccumulator::new(1, bound(2)).unwrap();
            assert!(scan.push(invalid).is_err());
            assert!(scan.finish().is_err());
        }
        let mut overflow = UsageAccumulator::new(1, bound(1)).unwrap();
        overflow.next_offset = u64::MAX;
        assert!(overflow.push(usage(vec![row("a", "1")])).is_err());
        assert!(overflow.rows.is_empty());
        assert!(overflow.finish().is_err());
    }

    #[test]
    fn unfinished_or_reused_accumulators_cannot_produce_results() {
        assert!(
            InventoryAccumulator::new(2, bound(1))
                .unwrap()
                .finish()
                .is_err()
        );
        assert!(
            UsageAccumulator::new(2, bound(1))
                .unwrap()
                .finish()
                .is_err()
        );
        assert!(InventoryAccumulator::new(0, bound(1)).is_err());
        assert!(InventoryAccumulator::new(101, bound(1)).is_err());
        assert!(UsageAccumulator::new(0, bound(1)).is_err());
        assert!(UsageAccumulator::new(5001, bound(1)).is_err());

        let mut inventory_scan = InventoryAccumulator::new(2, bound(1)).unwrap();
        inventory_scan.push(inventory(1, 0, 0, &[])).unwrap();
        assert!(inventory_scan.push(inventory(1, 0, 0, &[])).is_err());
        assert!(inventory_scan.finish().is_err());
        let mut usage_scan = UsageAccumulator::new(2, bound(1)).unwrap();
        usage_scan.push(usage(vec![])).unwrap();
        assert!(usage_scan.push(usage(vec![])).is_err());
        assert!(usage_scan.finish().is_err());
    }
}
