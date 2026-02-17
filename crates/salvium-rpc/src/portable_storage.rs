//! Epee portable storage binary format.
//!
//! Used by Salvium's `.bin` endpoints (get_blocks.bin, get_outs.bin, etc.).
//! This is the binary serialization format from the CryptoNote/Monero codebase.
//!
//! Reference: salvium/contrib/epee/include/storages/portable_storage.h
//!            portable-storage.js

use crate::error::RpcError;
use std::collections::HashMap;

// =============================================================================
// Constants
// =============================================================================

/// Portable storage signature bytes.
const SIGNATURE_A: u32 = 0x0111_0101;
const SIGNATURE_B: u32 = 0x0101_0201;

/// Current storage format version.
const FORMAT_VER: u8 = 1;

/// Type tags.
const TYPE_INT64: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT16: u8 = 3;
const TYPE_INT8: u8 = 4;
const TYPE_UINT64: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_UINT16: u8 = 7;
const TYPE_UINT8: u8 = 8;
const TYPE_DOUBLE: u8 = 9;
const TYPE_STRING: u8 = 10;
const TYPE_BOOL: u8 = 11;
const TYPE_OBJECT: u8 = 12;

/// Array flag (OR'd with element type).
const FLAG_ARRAY: u8 = 0x80;

// =============================================================================
// Values
// =============================================================================

/// A portable storage value.
#[derive(Debug, Clone)]
pub enum PsValue {
    Int64(i64),
    Int32(i32),
    Int16(i16),
    Int8(i8),
    Uint64(u64),
    Uint32(u32),
    Uint16(u16),
    Uint8(u8),
    Double(f64),
    String(Vec<u8>),
    Bool(bool),
    Object(HashMap<String, PsValue>),
    Array(Vec<PsValue>),
}

impl PsValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            PsValue::Uint64(v) => Some(*v),
            PsValue::Uint32(v) => Some(*v as u64),
            PsValue::Uint16(v) => Some(*v as u64),
            PsValue::Uint8(v) => Some(*v as u64),
            PsValue::Int64(v) => Some(*v as u64),
            PsValue::Int32(v) => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            PsValue::String(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            PsValue::String(v) => std::str::from_utf8(v).ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PsValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, PsValue>> {
        match self {
            PsValue::Object(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<PsValue>> {
        match self {
            PsValue::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&PsValue> {
        match self {
            PsValue::Object(m) => m.get(key),
            _ => None,
        }
    }
}

// =============================================================================
// Deserialization
// =============================================================================

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8, RpcError> {
        if self.remaining() < 1 {
            return Err(RpcError::PortableStorage("unexpected EOF".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_le(&mut self) -> Result<u16, RpcError> {
        if self.remaining() < 2 {
            return Err(RpcError::PortableStorage("unexpected EOF".into()));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> Result<u32, RpcError> {
        if self.remaining() < 4 {
            return Err(RpcError::PortableStorage("unexpected EOF".into()));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64_le(&mut self) -> Result<u64, RpcError> {
        if self.remaining() < 8 {
            return Err(RpcError::PortableStorage("unexpected EOF".into()));
        }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_i8(&mut self) -> Result<i8, RpcError> {
        Ok(self.read_u8()? as i8)
    }

    fn read_i16_le(&mut self) -> Result<i16, RpcError> {
        Ok(self.read_u16_le()? as i16)
    }

    fn read_i32_le(&mut self) -> Result<i32, RpcError> {
        Ok(self.read_u32_le()? as i32)
    }

    fn read_i64_le(&mut self) -> Result<i64, RpcError> {
        Ok(self.read_u64_le()? as i64)
    }

    fn read_f64_le(&mut self) -> Result<f64, RpcError> {
        let bits = self.read_u64_le()?;
        Ok(f64::from_bits(bits))
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, RpcError> {
        if self.remaining() < n {
            return Err(RpcError::PortableStorage("unexpected EOF".into()));
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// Read a varint-encoded count (Epee format).
    fn read_varint_count(&mut self) -> Result<usize, RpcError> {
        let first = self.read_u8()? as usize;
        let size_flag = first & 0x03;
        match size_flag {
            0 => Ok(first >> 2),
            1 => {
                let second = self.read_u8()? as usize;
                Ok((first | (second << 8)) >> 2)
            }
            2 => {
                let b = self.read_bytes(3)?;
                let val = first
                    | ((b[0] as usize) << 8)
                    | ((b[1] as usize) << 16)
                    | ((b[2] as usize) << 24);
                Ok(val >> 2)
            }
            _ => {
                // 8-byte varint (unlikely but supported)
                let b = self.read_bytes(7)?;
                let val = first as u64
                    | ((b[0] as u64) << 8)
                    | ((b[1] as u64) << 16)
                    | ((b[2] as u64) << 24)
                    | ((b[3] as u64) << 32)
                    | ((b[4] as u64) << 40)
                    | ((b[5] as u64) << 48)
                    | ((b[6] as u64) << 56);
                Ok((val >> 2) as usize)
            }
        }
    }

    fn read_string(&mut self) -> Result<Vec<u8>, RpcError> {
        let len = self.read_varint_count()?;
        self.read_bytes(len)
    }

    fn read_section_name(&mut self) -> Result<String, RpcError> {
        let len = self.read_u8()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes)
            .map_err(|e| RpcError::PortableStorage(format!("invalid UTF-8 in key: {}", e)))
    }

    fn read_value(&mut self, type_tag: u8) -> Result<PsValue, RpcError> {
        match type_tag {
            TYPE_INT64 => Ok(PsValue::Int64(self.read_i64_le()?)),
            TYPE_INT32 => Ok(PsValue::Int32(self.read_i32_le()?)),
            TYPE_INT16 => Ok(PsValue::Int16(self.read_i16_le()?)),
            TYPE_INT8 => Ok(PsValue::Int8(self.read_i8()?)),
            TYPE_UINT64 => Ok(PsValue::Uint64(self.read_u64_le()?)),
            TYPE_UINT32 => Ok(PsValue::Uint32(self.read_u32_le()?)),
            TYPE_UINT16 => Ok(PsValue::Uint16(self.read_u16_le()?)),
            TYPE_UINT8 => Ok(PsValue::Uint8(self.read_u8()?)),
            TYPE_DOUBLE => Ok(PsValue::Double(self.read_f64_le()?)),
            TYPE_STRING => Ok(PsValue::String(self.read_string()?)),
            TYPE_BOOL => Ok(PsValue::Bool(self.read_u8()? != 0)),
            TYPE_OBJECT => self.read_section().map(PsValue::Object),
            _ => Err(RpcError::PortableStorage(format!(
                "unknown type tag: {}",
                type_tag
            ))),
        }
    }

    fn read_entry(&mut self) -> Result<PsValue, RpcError> {
        let type_byte = self.read_u8()?;
        let is_array = type_byte & FLAG_ARRAY != 0;
        let elem_type = type_byte & !FLAG_ARRAY;

        if is_array {
            let count = self.read_varint_count()?;
            let mut arr = Vec::with_capacity(count);
            for _ in 0..count {
                arr.push(self.read_value(elem_type)?);
            }
            Ok(PsValue::Array(arr))
        } else {
            self.read_value(elem_type)
        }
    }

    fn read_section(&mut self) -> Result<HashMap<String, PsValue>, RpcError> {
        let count = self.read_varint_count()?;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            let name = self.read_section_name()?;
            let value = self.read_entry()?;
            map.insert(name, value);
        }
        Ok(map)
    }
}

/// Deserialize a portable storage binary buffer to a `PsValue::Object`.
pub fn deserialize(data: &[u8]) -> Result<PsValue, RpcError> {
    let mut reader = Reader::new(data);

    // Verify signature
    let sig_a = reader.read_u32_le()?;
    let sig_b = reader.read_u32_le()?;
    let ver = reader.read_u8()?;

    if sig_a != SIGNATURE_A || sig_b != SIGNATURE_B {
        return Err(RpcError::PortableStorage(format!(
            "bad signature: {:08x} {:08x}",
            sig_a, sig_b
        )));
    }
    if ver != FORMAT_VER {
        return Err(RpcError::PortableStorage(format!(
            "unsupported version: {}",
            ver
        )));
    }

    reader.read_section().map(PsValue::Object)
}

// =============================================================================
// Serialization
// =============================================================================

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn write_u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_i64_le(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_varint_count(&mut self, n: usize) {
        if n < 64 {
            self.write_u8((n << 2) as u8);
        } else if n < 16384 {
            self.write_u16_le((n << 2 | 1) as u16);
        } else if n < 1_073_741_824 {
            self.write_u32_le((n << 2 | 2) as u32);
        } else {
            self.write_u64_le((n << 2 | 3) as u64);
        }
    }

    fn write_string(&mut self, s: &[u8]) {
        self.write_varint_count(s.len());
        self.buf.extend_from_slice(s);
    }

    fn write_section_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        self.write_u8(bytes.len() as u8);
        self.buf.extend_from_slice(bytes);
    }

    fn write_value(&mut self, val: &PsValue) {
        match val {
            PsValue::Int64(v) => {
                self.write_u8(TYPE_INT64);
                self.write_i64_le(*v);
            }
            PsValue::Int32(v) => {
                self.write_u8(TYPE_INT32);
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
            PsValue::Int16(v) => {
                self.write_u8(TYPE_INT16);
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
            PsValue::Int8(v) => {
                self.write_u8(TYPE_INT8);
                self.write_u8(*v as u8);
            }
            PsValue::Uint64(v) => {
                self.write_u8(TYPE_UINT64);
                self.write_u64_le(*v);
            }
            PsValue::Uint32(v) => {
                self.write_u8(TYPE_UINT32);
                self.write_u32_le(*v);
            }
            PsValue::Uint16(v) => {
                self.write_u8(TYPE_UINT16);
                self.write_u16_le(*v);
            }
            PsValue::Uint8(v) => {
                self.write_u8(TYPE_UINT8);
                self.write_u8(*v);
            }
            PsValue::Double(v) => {
                self.write_u8(TYPE_DOUBLE);
                self.write_u64_le(v.to_bits());
            }
            PsValue::String(v) => {
                self.write_u8(TYPE_STRING);
                self.write_string(v);
            }
            PsValue::Bool(v) => {
                self.write_u8(TYPE_BOOL);
                self.write_u8(if *v { 1 } else { 0 });
            }
            PsValue::Object(m) => {
                self.write_u8(TYPE_OBJECT);
                self.write_section(m);
            }
            PsValue::Array(arr) => {
                if arr.is_empty() {
                    self.write_u8(FLAG_ARRAY | TYPE_UINT8);
                    self.write_varint_count(0);
                    return;
                }
                // Determine element type from first element
                let elem_type = match &arr[0] {
                    PsValue::Int64(_) => TYPE_INT64,
                    PsValue::Int32(_) => TYPE_INT32,
                    PsValue::Int16(_) => TYPE_INT16,
                    PsValue::Int8(_) => TYPE_INT8,
                    PsValue::Uint64(_) => TYPE_UINT64,
                    PsValue::Uint32(_) => TYPE_UINT32,
                    PsValue::Uint16(_) => TYPE_UINT16,
                    PsValue::Uint8(_) => TYPE_UINT8,
                    PsValue::Double(_) => TYPE_DOUBLE,
                    PsValue::String(_) => TYPE_STRING,
                    PsValue::Bool(_) => TYPE_BOOL,
                    PsValue::Object(_) => TYPE_OBJECT,
                    PsValue::Array(_) => TYPE_UINT8, // nested arrays not standard
                };
                self.write_u8(FLAG_ARRAY | elem_type);
                self.write_varint_count(arr.len());
                for item in arr {
                    self.write_value_only(item);
                }
            }
        }
    }

    /// Write just the value bytes (no type tag) — used for array elements.
    fn write_value_only(&mut self, val: &PsValue) {
        match val {
            PsValue::Int64(v) => self.write_i64_le(*v),
            PsValue::Int32(v) => self.buf.extend_from_slice(&v.to_le_bytes()),
            PsValue::Int16(v) => self.buf.extend_from_slice(&v.to_le_bytes()),
            PsValue::Int8(v) => self.write_u8(*v as u8),
            PsValue::Uint64(v) => self.write_u64_le(*v),
            PsValue::Uint32(v) => self.write_u32_le(*v),
            PsValue::Uint16(v) => self.write_u16_le(*v),
            PsValue::Uint8(v) => self.write_u8(*v),
            PsValue::Double(v) => self.write_u64_le(v.to_bits()),
            PsValue::String(v) => self.write_string(v),
            PsValue::Bool(v) => self.write_u8(if *v { 1 } else { 0 }),
            PsValue::Object(m) => self.write_section(m),
            PsValue::Array(_) => {} // nested arrays not standard
        }
    }

    fn write_section(&mut self, map: &HashMap<String, PsValue>) {
        self.write_varint_count(map.len());
        for (key, val) in map {
            self.write_section_name(key);
            self.write_value(val);
        }
    }
}

/// Serialize a `PsValue::Object` to portable storage binary format.
pub fn serialize(root: &HashMap<String, PsValue>) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32_le(SIGNATURE_A);
    w.write_u32_le(SIGNATURE_B);
    w.write_u8(FORMAT_VER);
    w.write_section(root);
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_simple() {
        let mut map = HashMap::new();
        map.insert("height".to_string(), PsValue::Uint64(12345));
        map.insert("active".to_string(), PsValue::Bool(true));
        map.insert(
            "name".to_string(),
            PsValue::String(b"salvium".to_vec()),
        );

        let bytes = serialize(&map);
        let result = deserialize(&bytes).unwrap();

        let obj = result.as_object().unwrap();
        assert_eq!(obj["height"].as_u64(), Some(12345));
        assert_eq!(obj["active"].as_bool(), Some(true));
        assert_eq!(obj["name"].as_str(), Some("salvium"));
    }

    #[test]
    fn test_roundtrip_array() {
        let mut map = HashMap::new();
        map.insert(
            "values".to_string(),
            PsValue::Array(vec![
                PsValue::Uint64(1),
                PsValue::Uint64(2),
                PsValue::Uint64(3),
            ]),
        );

        let bytes = serialize(&map);
        let result = deserialize(&bytes).unwrap();

        let arr = result.get("values").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_u64(), Some(1));
        assert_eq!(arr[2].as_u64(), Some(3));
    }

    #[test]
    fn test_roundtrip_nested_object() {
        let mut inner = HashMap::new();
        inner.insert("x".to_string(), PsValue::Uint32(42));

        let mut map = HashMap::new();
        map.insert("nested".to_string(), PsValue::Object(inner));

        let bytes = serialize(&map);
        let result = deserialize(&bytes).unwrap();

        let nested = result.get("nested").unwrap().as_object().unwrap();
        assert_eq!(nested["x"].as_u64(), Some(42));
    }

    #[test]
    fn test_signature_validation() {
        let bad_data = vec![0u8; 20];
        assert!(deserialize(&bad_data).is_err());
    }

    #[test]
    fn test_empty_section() {
        let map = HashMap::new();
        let bytes = serialize(&map);
        let result = deserialize(&bytes).unwrap();
        assert!(result.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_varint_count_sizes() {
        // Test that varint encoding/decoding roundtrips for various sizes
        for &count in &[0usize, 1, 63, 64, 100, 16383, 16384, 100_000] {
            let mut w = Writer::new();
            w.write_varint_count(count);
            let mut r = Reader::new(&w.buf);
            let decoded = r.read_varint_count().unwrap();
            assert_eq!(decoded, count, "varint roundtrip failed for {}", count);
        }
    }
}
