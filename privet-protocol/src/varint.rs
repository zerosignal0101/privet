
use crate::error::FrameError;

pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_len(value));
    loop {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
            out.push(b);
        } else {
            out.push(b);
            break;
        }
    }
    out
}

pub fn decode_varint(buf: &mut &[u8]) -> Result<u64, FrameError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut count = 0usize;
    loop {
        if count >= 10 {
            return Err(FrameError::VarintOverflow);
        }
        let &b = buf.first().ok_or(FrameError::UnexpectedEof)?;
        *buf = &buf[1..];
        result |= ((b & 0x7F) as u64)
            .checked_shl(shift)
            .ok_or(FrameError::VarintOverflow)?;
        shift += 7;
        count += 1;
        if b & 0x80 == 0 {
            if count == 10 && (b & 0xFE) != 0 {
                return Err(FrameError::VarintOverflow);
            }
            return Ok(result);
        }
    }
}

pub fn varint_len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}
