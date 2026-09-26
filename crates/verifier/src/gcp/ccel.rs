//! TCG crypto-agile CCEL framing and Intel RTMR replay. All decoded lengths
//! are checked against the already bounded input before slicing/allocation.
//! CC MR indices are 1..=4 for RTMR[0..=3], not TPM PCR indices.
//! Reference: google/go-eventlog 65d54cb8f3fb1a6ccb3f0a0a6e247e5c13a4bc04,
//! tcg/pfpformat.go and register/rtmr.go. No firmware workarounds are applied.
use super::GcpWorkloadIssue as Issue;
use ez_hash::{Hasher, Sha384};
use std::collections::BTreeMap;
use zrpc_protocol::MAX_ATTESTATION_RESPONSE_BYTES;

pub(super) const EV_NO_ACTION: u32 = 3;
pub(super) const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
const TPM_ALG_SHA384: u16 = 0x000c;

pub(super) struct Event<'a> {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 48],
    pub data: &'a [u8],
}

pub(super) struct Ccel<'a> {
    pub spec_id: &'a [u8],
    pub events: Vec<Event<'a>>,
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Issue> {
        let value = self.0.get(..count).ok_or(Issue::MalformedCcel)?;
        self.0 = self.0.get(count..).ok_or(Issue::MalformedCcel)?;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, Issue> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Issue> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Issue::MalformedCcel)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Issue> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Issue::MalformedCcel)?,
        ))
    }
    fn blob(&mut self) -> Result<&'a [u8], Issue> {
        let count = usize::try_from(self.u32()?).map_err(|_| Issue::MalformedCcel)?;
        self.take(count)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Ccel<'_>, Issue> {
    // Wire evidence is hex, so this is an upper bound derived from the existing
    // protocol body limit, not a new provider-sized limit.
    if bytes.is_empty() || bytes.len() > MAX_ATTESTATION_RESPONSE_BYTES / 2 {
        return Err(Issue::MalformedCcel);
    }
    let mut input = Cursor(bytes);
    if input.u32()? != 1 || input.u32()? != EV_NO_ACTION || input.take(20)? != [0; 20] {
        return Err(Issue::UnsupportedCcel);
    }
    let spec_id = input.blob()?;
    let mut header = Cursor(spec_id);
    if header.take(16)? != b"Spec ID Event03\0" {
        return Err(Issue::UnsupportedCcel);
    }
    let _platform_class = header.u32()?;
    let minor = header.u8()?;
    let major = header.u8()?;
    let _errata = header.u8()?;
    let uintn_size = header.u8()?;
    if minor != 0 || major != 2 || !matches!(uintn_size, 1 | 2) {
        return Err(Issue::UnsupportedCcel);
    }
    let algorithm_count = header.u32()?;
    // Each algorithm declaration is four bytes. Do not allocate from its count.
    if algorithm_count == 0 || algorithm_count as usize > header.0.len() / 4 {
        return Err(Issue::MalformedCcel);
    }
    let mut algorithms = BTreeMap::new();
    for _ in 0..algorithm_count {
        let id = header.u16()?;
        let size = header.u16()?;
        let expected = match id {
            0x0004 => 20,
            0x000b => 32,
            TPM_ALG_SHA384 => 48,
            0x000d => 64,
            _ => return Err(Issue::UnsupportedCcel),
        };
        if size != expected || algorithms.insert(id, size).is_some() {
            return Err(Issue::MalformedCcel);
        }
    }
    if algorithms.get(&TPM_ALG_SHA384) != Some(&48) {
        return Err(Issue::UnsupportedCcel);
    }
    let vendor_len = header.u8()? as usize;
    header.take(vendor_len)?;
    if !header.0.is_empty() {
        return Err(Issue::MalformedCcel);
    }
    let mut events = Vec::new();
    while !input.0.is_empty() {
        // Firmware exposes a fixed CCEL area padded with zero or ff. Accept
        // only a uniform entire suffix, never a marker followed by hidden data.
        if matches!(input.0.first(), Some(0) | Some(255))
            && input.0.iter().all(|b| *b == input.0[0])
        {
            break;
        }
        let mr_index = input.u32()?;
        let event_type = input.u32()?;
        if !(1..=4).contains(&mr_index) {
            return Err(Issue::UnsupportedCcel);
        }
        let digest_count = input.u32()?;
        if digest_count as usize != algorithms.len() {
            return Err(Issue::MalformedCcel);
        }
        let mut seen = BTreeMap::new();
        let mut digest = None;
        for _ in 0..digest_count {
            let id = input.u16()?;
            let size = *algorithms.get(&id).ok_or(Issue::MalformedCcel)? as usize;
            if seen.insert(id, ()).is_some() {
                return Err(Issue::MalformedCcel);
            }
            let value = input.take(size)?;
            if id == TPM_ALG_SHA384 {
                digest = Some(value.try_into().map_err(|_| Issue::MalformedCcel)?);
            }
        }
        let digest = digest.ok_or(Issue::MalformedCcel)?;
        let data = input.blob()?;
        events.push(Event {
            mr_index,
            event_type,
            digest,
            data,
        });
    }
    if events.is_empty() {
        return Err(Issue::MalformedCcel);
    }
    Ok(Ccel { spec_id, events })
}

pub(super) fn replay(events: &[Event<'_>]) -> [[u8; 48]; 4] {
    let mut registers = [[0u8; 48]; 4];
    for event in events {
        if event.event_type == EV_NO_ACTION {
            continue;
        }
        // parse() establishes this index and is the sole event constructor in
        // production. get_mut still makes that invariant explicit here.
        if let Some(register) = event
            .mr_index
            .checked_sub(1)
            .and_then(|i| registers.get_mut(i as usize))
        {
            let mut extend = [0u8; 96];
            extend[..48].copy_from_slice(register);
            extend[48..].copy_from_slice(&event.digest);
            *register = Sha384::hash(&extend);
        }
    }
    registers
}
