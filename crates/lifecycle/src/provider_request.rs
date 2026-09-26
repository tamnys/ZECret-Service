//! Fixed read-only routes from the pinned Phala lifecycle source contract.
//! This module builds origin-form paths only; it cannot select an origin,
//! credential, workspace, HTTP mutation, or provider-returned URL.

use crate::LifecycleError;
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

/// Internal request vocabulary. Every field is validated before a path is
/// returned. Request scope and TLS authentication belong to the transport.
pub(crate) enum ReadRequest<'a> {
    Authenticate,
    Inventory {
        page: u64,
        page_size: u64,
    },
    Detail {
        cvm_id: &'a str,
    },
    Usage {
        app_id: &'a str,
        start_unix_seconds: u64,
        end_unix_seconds: u64,
        limit: u64,
        offset: u64,
    },
}

const INVALID: LifecycleError = LifecycleError("invalid Phala lifecycle read request");

impl ReadRequest<'_> {
    pub(crate) fn method(&self) -> &'static str {
        "GET"
    }

    /// Produce the exact origin-form target. The caller must not apply URL
    /// joining, path normalization, or another round of percent encoding.
    pub(crate) fn path_and_query(&self) -> Result<String, LifecycleError> {
        match self {
            Self::Authenticate => Ok("/api/v1/auth/me".to_owned()),
            Self::Inventory { page, page_size } => {
                // Pinned OpenAPI: page >= 1 and page_size in 1..=100.
                if *page == 0 || !(1..=100).contains(page_size) {
                    return Err(INVALID);
                }
                Ok(format!(
                    "/api/v1/cvms/paginated?page={page}&page_size={page_size}"
                ))
            }
            Self::Detail { cvm_id } => Ok(format!("/api/v1/cvms/{}", path_segment(cvm_id)?)),
            Self::Usage {
                app_id,
                start_unix_seconds,
                end_unix_seconds,
                limit,
                offset,
            } => {
                // Pinned OpenAPI: limit in 1..=5000, offset >= 0. Requiring an
                // explicit ordered window prevents the provider's seven-day
                // omitted-date default from discarding experiment history.
                if start_unix_seconds > end_unix_seconds || !(1..=5000).contains(limit) {
                    return Err(INVALID);
                }
                let app = path_segment(app_id)?;
                let start = utc_seconds(*start_unix_seconds)?;
                let end = utc_seconds(*end_unix_seconds)?;
                Ok(format!(
                    "/api/v1/apps/{app}/usage?start_date={}&end_date={}&limit={limit}&offset={offset}",
                    utf8_percent_encode(&start, NON_ALPHANUMERIC),
                    utf8_percent_encode(&end, NON_ALPHANUMERIC),
                ))
            }
        }
    }
}

fn path_segment(value: &str) -> Result<String, LifecycleError> {
    // The versioned SDK's returned IDs are strings without a closed grammar.
    // Do not invent aliases or a provider-ID regex. Reject path separators and
    // dot segments so ordinary server-side percent decoding cannot turn the
    // selected ID into another route. Literal percent signs are encoded too;
    // this does not make claims about provider double-decoding behavior.
    if value.trim().is_empty() || value == "." || value == ".." || value.contains(['/', '\\']) {
        return Err(INVALID);
    }
    Ok(utf8_percent_encode(value, NON_ALPHANUMERIC).to_string())
}

fn utc_seconds(timestamp: u64) -> Result<String, LifecycleError> {
    let timestamp = i64::try_from(timestamp).map_err(|_| INVALID)?;
    let value = DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or(INVALID)?;
    // OpenAPI format `date-time` uses RFC 3339's four-digit full-year grammar;
    // chrono also represents expanded ISO years that are outside that grammar.
    if !(0..=9999).contains(&value.year()) {
        return Err(INVALID);
    }
    Ok(value.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_routes_are_get_only_and_preserve_explicit_pagination() {
        let cases = [
            (ReadRequest::Authenticate, "/api/v1/auth/me".to_owned()),
            (
                ReadRequest::Inventory {
                    page: 1,
                    page_size: 30,
                },
                "/api/v1/cvms/paginated?page=1&page_size=30".to_owned(),
            ),
            (
                ReadRequest::Inventory {
                    page: u64::MAX,
                    page_size: 100,
                },
                format!("/api/v1/cvms/paginated?page={}&page_size=100", u64::MAX),
            ),
            (
                ReadRequest::Detail { cvm_id: "cvm_123" },
                "/api/v1/cvms/cvm%5F123".to_owned(),
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(request.method(), "GET");
            assert_eq!(request.path_and_query().unwrap(), expected);
        }
        for (page, page_size) in [(0, 30), (1, 0), (1, 101), (1, u64::MAX)] {
            assert!(
                ReadRequest::Inventory { page, page_size }
                    .path_and_query()
                    .is_err()
            );
        }
    }

    #[test]
    fn opaque_id_metacharacters_and_unicode_remain_encoded_in_one_segment() {
        for (id, encoded) in [
            (
                "id?limit=1&offset=2#fragment",
                "id%3Flimit%3D1%26offset%3D2%23fragment",
            ),
            ("%2F..%2fother", "%252F%2E%2E%252fother"),
            ("quoted\"id", "quoted%22id"),
            (" id ", "%20id%20"),
            ("cvm.例", "cvm%2E%E4%BE%8B"),
            ("id\r\nHeader:value", "id%0D%0AHeader%3Avalue"),
        ] {
            assert_eq!(
                ReadRequest::Detail { cvm_id: id }.path_and_query().unwrap(),
                format!("/api/v1/cvms/{encoded}")
            );
            let usage = ReadRequest::Usage {
                app_id: id,
                start_unix_seconds: 0,
                end_unix_seconds: 1,
                limit: 1,
                offset: 0,
            }
            .path_and_query()
            .unwrap();
            assert!(usage.starts_with(&format!("/api/v1/apps/{encoded}/usage?")));
            assert_eq!(usage.matches('?').count(), 1);
            assert_eq!(usage.matches('&').count(), 3);
        }
    }

    #[test]
    fn empty_and_structural_path_ids_are_rejected_in_both_routes() {
        for id in [
            "",
            " ",
            "\t",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../auth/me",
            "//host",
        ] {
            assert!(ReadRequest::Detail { cvm_id: id }.path_and_query().is_err());
            assert!(
                ReadRequest::Usage {
                    app_id: id,
                    start_unix_seconds: 0,
                    end_unix_seconds: 1,
                    limit: 1,
                    offset: 0,
                }
                .path_and_query()
                .is_err()
            );
        }
    }

    #[test]
    fn usage_window_is_explicit_and_utc_with_documented_numeric_bounds() {
        let request = ReadRequest::Usage {
            app_id: "abc123",
            start_unix_seconds: 0,
            end_unix_seconds: 86_400,
            limit: 5000,
            offset: u64::MAX,
        };
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.path_and_query().unwrap(),
            format!(
                "/api/v1/apps/abc123/usage?start_date=1970%2D01%2D01T00%3A00%3A00Z&end_date=1970%2D01%2D02T00%3A00%3A00Z&limit=5000&offset={}",
                u64::MAX
            )
        );
        for (start, end, limit) in [(1, 0, 1), (0, 1, 0), (0, 1, 5001)] {
            assert!(
                ReadRequest::Usage {
                    app_id: "abc123",
                    start_unix_seconds: start,
                    end_unix_seconds: end,
                    limit,
                    offset: 0,
                }
                .path_and_query()
                .is_err()
            );
        }
    }

    #[test]
    fn date_representation_overflow_is_rejected_without_panicking() {
        assert_eq!(
            utc_seconds(253_402_300_799).unwrap(),
            "9999-12-31T23:59:59Z"
        );
        for timestamp in [253_402_300_800, i64::MAX as u64, u64::MAX] {
            assert!(utc_seconds(timestamp).is_err());
            assert!(
                ReadRequest::Usage {
                    app_id: "abc123",
                    start_unix_seconds: 0,
                    end_unix_seconds: timestamp,
                    limit: 1,
                    offset: 0,
                }
                .path_and_query()
                .is_err()
            );
        }
        assert!(
            ReadRequest::Usage {
                app_id: "abc123",
                start_unix_seconds: 0,
                end_unix_seconds: 0,
                limit: 1,
                offset: 0,
            }
            .path_and_query()
            .is_ok()
        );
    }
}
