//! Minimal RLP decoder for EIP-1559 (type 0x02) transactions.
//! Extracts `to` and `value` to bind a signing request to an evaluated intent.

/// Parsed fields needed for policy binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthTxFields {
    /// 20-byte destination address (lowercase hex, 0x-prefixed). None for contract creation.
    pub to: Option<[u8; 20]>,
    /// Transfer value in wei.
    pub value: u128,
}

fn decode_len(bytes: &[u8]) -> Option<(usize, usize)> {
    // returns (payload_offset, payload_len)
    if bytes.is_empty() {
        return None;
    }
    let b = bytes[0];
    if b <= 0x7f {
        Some((0, 1))
    } else if b <= 0xb7 {
        let len = (b - 0x80) as usize;
        if bytes.len() < 1 + len {
            return None;
        }
        Some((1, len))
    } else if b <= 0xbf {
        let l_of_l = (b - 0xb7) as usize;
        if bytes.len() < 1 + l_of_l {
            return None;
        }
        let mut len = 0usize;
        for &x in &bytes[1..1 + l_of_l] {
            len = len.checked_mul(256)?.checked_add(x as usize)?;
        }
        if bytes.len() < 1 + l_of_l + len {
            return None;
        }
        Some((1 + l_of_l, len))
    } else if b <= 0xf7 {
        let len = (b - 0xc0) as usize;
        if bytes.len() < 1 + len {
            return None;
        }
        Some((1, len))
    } else {
        let l_of_l = (b - 0xf7) as usize;
        if bytes.len() < 1 + l_of_l {
            return None;
        }
        let mut len = 0usize;
        for &x in &bytes[1..1 + l_of_l] {
            len = len.checked_mul(256)?.checked_add(x as usize)?;
        }
        if bytes.len() < 1 + l_of_l + len {
            return None;
        }
        Some((1 + l_of_l, len))
    }
}

fn item_bytes(bytes: &[u8]) -> Option<&[u8]> {
    let (off, len) = decode_len(bytes)?;
    if bytes[0] >= 0xc0 {
        // list: payload is the encoded list content in this helper we only call for strings
        None
    } else {
        Some(&bytes[off..off + len])
    }
}

fn item_total_len(bytes: &[u8]) -> Option<usize> {
    let (off, len) = decode_len(bytes)?;
    Some(off + len)
}

/// Decode an RLP list into item slices.
fn decode_list(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let (off, len) = decode_len(bytes)?;
    if bytes[0] < 0xc0 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = off;
    let end = off + len;
    if end > bytes.len() {
        return None;
    }
    while i < end {
        let t = item_total_len(&bytes[i..])?;
        out.push(&bytes[i..i + t]);
        i += t;
    }
    if i != end {
        return None;
    }
    Some(out)
}

fn decode_u128(bytes: &[u8]) -> Option<u128> {
    // bytes is a full RLP string item
    let b = item_bytes(bytes)?;
    if b.len() > 16 {
        return None;
    }
    let mut v: u128 = 0;
    for &x in b {
        v = (v << 8) | (x as u128);
    }
    Some(v)
}

fn decode_address(bytes: &[u8]) -> Option<Option<[u8; 20]>> {
    let b = item_bytes(bytes)?;
    if b.is_empty() {
        return Some(None);
    }
    if b.len() != 20 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(b);
    Some(Some(a))
}

pub fn to_hex_lower(addr: &[u8; 20]) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in addr {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse EIP-1559 (0x02) transaction raw bytes and return (to, value).
pub fn parse_eip1559(raw: &[u8]) -> Option<EthTxFields> {
    if raw.len() < 2 || raw[0] != 0x02 {
        return None;
    }
    let items = decode_list(&raw[1..])?;
    // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, ...]
    if items.len() < 7 {
        return None;
    }
    let to = decode_address(items[5])?;
    let value = decode_u128(items[6])?;
    Some(EthTxFields { to, value })
}
