use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum BytePacketBufferError {
    EndOfBuffer,
    JumpLimitExceeded,
}

impl Display for BytePacketBufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.source())
    }
}

impl Error for BytePacketBufferError {}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specified number of steps
    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8, BytePacketBufferError> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8, BytePacketBufferError> {
        if pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], BytePacketBufferError> {
        if start + len >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer);
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16, BytePacketBufferError> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32, BytePacketBufferError> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);
        Ok(res)
    }

    /// Read a qname
    ///
    /// It is difficult to read domain names while taking labels into consideration.
    /// Can achieve via [3]www[6]google[3]com[0] and app www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), BytePacketBufferError> {
        // Track position locally as jumps can occurr.
        // This allows us to move past the current qname while keeping a position
        // in the current qname.
        let mut pos = self.pos();

        // track if we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps = 0;

        // delimiter to append to labels. Leave empty at start then change to "."
        // after first iteration
        let mut delim = "";
        loop {
            // prevent malicious packets that contain a cycle in their jump instructions
            if jumps > max_jumps {
                return Err(BytePacketBufferError::JumpLimitExceeded);
            }
            let len = self.get(pos)?; // labels start with length byte

            // if len has 2 most significant bits set, we should jump
            if (len & 0xC0) == 0xC0 {
                // update buffer position to outside of current label
                if !jumped {
                    self.seek(pos + 2);
                }

                // read another byte, calc offset and jump
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) * 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps += 1;
                continue;
            } else {
                // we read a label and append to output
                pos += 1; // move out of length byte
                if len == 0 {
                    // domain names terminated by empty label of length 0
                    break;
                }
                outstr.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos);
        }
        Ok(())
    }
}
