//! Multi-request scans over the existing synthetic TLS fixture. These tests
//! exercise network sequencing; pure accumulator validation has separate tests.
use super::*;
use serde_json::json;

fn inventory(ids: &[&str], page: u64, total: u64, pages: u64) -> String {
    json!({
        "items": ids.iter().map(|id| json!({
            "id": id, "status": "running", "app_id": "synthetic_app",
            "instance_id": "synthetic_instance", "vm_uuid": "synthetic_uuid",
            "workspace": {"object_type": "workspace", "id": WORKSPACE}
        })).collect::<Vec<_>>(),
        "total": total, "page": page, "page_size": 2, "pages": pages
    })
    .to_string()
}

fn usage(keys: &[&str]) -> String {
    // Exact integer zero is sufficient for pagination; monetary lexeme
    // preservation and billing identity are covered by the wire/amount tests.
    json!({
        "usage": keys.iter().map(|key| json!({
            "instance_id": "synthetic_uuid", "project_id": 11, "team_id": 22,
            "timestamp": "1970-01-01T00:00:00Z", "event_type": "synthetic",
            "usage_type": "compute", "billing_start": "1970-01-01",
            "billing_end": "1970-01-02", "billing_key": key,
            "billing_hour": "1970-01-01T00:00:00Z", "billing_day": "1970-01-01",
            "cost": 0
        })).collect::<Vec<_>>(),
        "total": keys.len(), "total_cost": 0
    })
    .to_string()
}

fn bound(bodies: &[&str]) -> usize {
    bodies
        .iter()
        .map(|body| body.len())
        .chain([AUTH.len()])
        .max()
        .unwrap()
}

fn records(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).unwrap()
}

fn paths(server: &Server) -> Vec<String> {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| {
            let mut line = request.lines().next().unwrap().split(' ');
            assert_eq!(line.next(), Some("GET"));
            let path = line.next().unwrap().to_owned();
            assert_eq!(line.next(), Some("HTTP/1.1"));
            assert_eq!(header_value(request, "x-phala-workspace"), Some(WORKSPACE));
            assert_eq!(
                header_value(request, "x-phala-version"),
                Some(provider_wire::PHALA_API_VERSION)
            );
            path
        })
        .collect()
}

#[tokio::test]
async fn inventory_scan_reads_each_declared_page_and_returns_all_items() {
    let first = inventory(&["synthetic_a", "synthetic_b"], 1, 3, 2);
    let last = inventory(&["synthetic_c"], 2, 3, 2);
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", &first),
            response("200 OK", &last),
        ],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first, &last]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    let scan = reads.inventory_scan(2, records(3)).await.unwrap();
    let mut ids: Vec<_> = scan.items().iter().map(|item| item.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["synthetic_a", "synthetic_b", "synthetic_c"]);
    server.wait_closed(3).await;
    assert_eq!(
        paths(&server),
        [
            "/api/v1/auth/me",
            "/api/v1/cvms/paginated?page=1&page_size=2",
            "/api/v1/cvms/paginated?page=2&page_size=2",
        ]
    );
}

#[tokio::test]
async fn usage_scan_continues_after_short_pages_with_one_window_until_empty() {
    let first = usage(&["synthetic_first"]);
    let second = usage(&["synthetic_second"]);
    let empty = usage(&[]);
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", &first),
            response("200 OK", &second),
            response("200 OK", &empty),
        ],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first, &second, &empty]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    // Exactly the retained-record bound still permits the required empty-page
    // request. A short page itself never proves completion.
    let scan = reads
        .usage_scan("synthetic_app", 0, 1, 2, records(2))
        .await
        .unwrap();
    let mut keys: Vec<_> = scan
        .rows()
        .iter()
        .map(|row| row.billing_key.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["synthetic_first", "synthetic_second"]);
    server.wait_closed(4).await;
    let expected: Vec<_> = [0, 1, 2].into_iter().map(|offset| format!(
        "/api/v1/apps/synthetic%5Fapp/usage?start_date=1970%2D01%2D01T00%3A00%3A00Z&end_date=1970%2D01%2D01T00%3A00%3A01Z&limit=2&offset={offset}"
    )).collect();
    let actual = paths(&server);
    assert_eq!(actual[0], "/api/v1/auth/me");
    assert_eq!(&actual[1..], expected);
}

#[tokio::test]
async fn changed_duplicate_incomplete_or_failed_inventory_has_no_scan_result() {
    let first = inventory(&["synthetic_a", "synthetic_b"], 1, 3, 2);
    let malformed_last_pages = [
        inventory(&["synthetic_c"], 2, 4, 2),
        inventory(&["synthetic_b"], 2, 3, 2),
        inventory(&[], 2, 3, 2),
        inventory(&["synthetic_c"], 3, 3, 2),
    ];
    for last in malformed_last_pages {
        let server = Server::start(
            vec![
                response("200 OK", AUTH),
                response("200 OK", &first),
                response("200 OK", &last),
            ],
            HOST,
        )
        .await;
        let mut reads = server
            .client(bound(&[&first, &last]))
            .authenticate()
            .await
            .ok()
            .unwrap();
        assert_eq!(
            reads.inventory_scan(2, records(4)).await.err(),
            Some(ProviderHttpError::InvalidResponse)
        );
        server.wait_closed(3).await;
        assert_eq!(paths(&server).len(), 3);
    }
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", &first),
            response("503 Service Unavailable", "synthetic failure"),
        ],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    assert_eq!(
        reads.inventory_scan(2, records(3)).await.err(),
        Some(ProviderHttpError::ProviderUnavailable)
    );
    server.wait_closed(3).await;
    assert_eq!(paths(&server).len(), 3);
}

#[tokio::test]
async fn repeated_usage_key_or_http_failure_does_not_finish_or_retry_a_scan() {
    let first = usage(&["synthetic_repeated"]);
    for (reply, error) in [
        (
            response("200 OK", &first),
            ProviderHttpError::InvalidResponse,
        ),
        (
            response("429 Too Many Requests", "synthetic failure"),
            ProviderHttpError::RateLimited,
        ),
    ] {
        let server = Server::start(
            vec![response("200 OK", AUTH), response("200 OK", &first), reply],
            HOST,
        )
        .await;
        let mut reads = server
            .client(bound(&[&first]))
            .authenticate()
            .await
            .ok()
            .unwrap();
        assert_eq!(
            reads
                .usage_scan("synthetic_app", 0, 1, 2, records(2))
                .await
                .err(),
            Some(error)
        );
        server.wait_closed(3).await;
        assert_eq!(paths(&server).len(), 3);
    }
}

#[tokio::test]
async fn caller_record_bound_prevents_an_oversized_inventory_or_usage_scan() {
    let first = inventory(&["synthetic_a", "synthetic_b"], 1, 3, 2);
    let server = Server::start(
        vec![response("200 OK", AUTH), response("200 OK", &first)],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    assert_eq!(
        reads.inventory_scan(2, records(2)).await.err(),
        Some(ProviderHttpError::InvalidResponse)
    );
    server.wait_closed(2).await;
    assert_eq!(paths(&server).len(), 2);

    let first = usage(&["synthetic_first"]);
    let second = usage(&["synthetic_second"]);
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", &first),
            response("200 OK", &second),
        ],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first, &second]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    assert_eq!(
        reads
            .usage_scan("synthetic_app", 0, 1, 2, records(1))
            .await
            .err(),
        Some(ProviderHttpError::InvalidResponse)
    );
    server.wait_closed(3).await;
    assert_eq!(paths(&server).len(), 3);
}

#[tokio::test]
async fn scanner_pages_share_the_original_deadline_and_cancel_an_incomplete_body() {
    let first = inventory(&["synthetic_a", "synthetic_b"], 1, 3, 2);
    let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".to_vec();
    let server = Server::start(
        vec![
            response("200 OK", AUTH),
            response("200 OK", &first),
            partial,
        ],
        HOST,
    )
    .await;
    let mut reads = server
        .client(bound(&[&first]))
        .authenticate()
        .await
        .ok()
        .unwrap();
    let deadline = reads.0.deadline;
    tokio::time::pause();
    tokio::time::advance(TEST_BUDGET / 2).await;
    tokio::time::resume();
    let task = tokio::spawn(async move { reads.inventory_scan(2, records(3)).await });
    server.wait_requests(3).await;
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    assert_eq!(
        task.await.unwrap().err(),
        Some(ProviderHttpError::DeadlineExceeded)
    );
    // Tokio's timer granularity can schedule expiry just after the exact
    // deadline. A renewed scan/page budget would instead expire no earlier
    // than the original deadline plus the half-budget advanced before starting
    // this scan. Compare those distinct synthetic boundaries, without inventing
    // a scheduler tolerance or requiring exact timer equality.
    assert!(Instant::now() < deadline + TEST_BUDGET / 2);
    tokio::time::resume();
    server.wait_closed(3).await;
    assert_eq!(paths(&server).len(), 3);
}
