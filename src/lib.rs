use std::vec::Vec;

///
/// DecryptedState is a marker struct used to indicate that the data is decrypted.
/// 
pub struct DecryptedState;
///
/// EncryptedState is a marker struct used to indicate that the data is encrypted.
/// 
pub struct EncryptedState;

///
/// AESBlock is a struct that represents a single 16 byte block of data. 
/// It can be used to encrypt or decrypt the data based on the state the 
/// struct was created.
/// 
/// The struct is generic over the state. The state can be either DecryptedState
/// or EncryptedState. This is to ensure that the data is not encrypted or decrypted twice.
/// 
/// The struct contains a grid of 16 bytes. This grid is considered to be a 4x4 grid with
/// row-major order. This means that the first 4 bytes are the first row, the next 4 bytes
/// are the second row and so on.
///  
pub struct AESBlock<State = DecryptedState> {
    grid: Vec<u8>,
    state: std::marker::PhantomData<State>
}

/// 
/// AESData is a struct containg a vector of bytes. This struct can be used to encrypt or decrypt
/// the included data. 
/// 
pub struct AESData<State = DecryptedState> {
    data: Vec<u8>,
    state: std::marker::PhantomData<State>
}

///
/// Implementation of the decrypted AESBlock struct.
///
impl AESBlock<DecryptedState> {

    ///
    /// Substitutes each byte in the data with the corresponding byte in the s_box.
    /// 
    pub const S_BOX: [&'static u8; 256] = [ &0x63,&0x7c,&0x77,&0x7b,&0xf2,&0x6b,&0x6f,&0xc5,&0x30,&0x01,&0x67,&0x2b,&0xfe,&0xd7,&0xab,&0x76,
                                        &0xca,&0x82,&0xc9,&0x7d,&0xfa,&0x59,&0x47,&0xf0,&0xad,&0xd4,&0xa2,&0xaf,&0x9c,&0xa4,&0x72,&0xc0,
                                        &0xb7,&0xfd,&0x93,&0x26,&0x36,&0x3f,&0xf7,&0xcc,&0x34,&0xa5,&0xe5,&0xf1,&0x71,&0xd8,&0x31,&0x15,
                                        &0x04,&0xc7,&0x23,&0xc3,&0x18,&0x96,&0x05,&0x9a,&0x07,&0x12,&0x80,&0xe2,&0xeb,&0x27,&0xb2,&0x75,
                                        &0x09,&0x83,&0x2c,&0x1a,&0x1b,&0x6e,&0x5a,&0xa0,&0x52,&0x3b,&0xd6,&0xb3,&0x29,&0xe3,&0x2f,&0x84,
                                        &0x53,&0xd1,&0x00,&0xed,&0x20,&0xfc,&0xb1,&0x5b,&0x6a,&0xcb,&0xbe,&0x39,&0x4a,&0x4c,&0x58,&0xcf,
                                        &0xd0,&0xef,&0xaa,&0xfb,&0x43,&0x4d,&0x33,&0x85,&0x45,&0xf9,&0x02,&0x7f,&0x50,&0x3c,&0x9f,&0xa8,
                                        &0x51,&0xa3,&0x40,&0x8f,&0x92,&0x9d,&0x38,&0xf5,&0xbc,&0xb6,&0xda,&0x21,&0x10,&0xff,&0xf3,&0xd2,
                                        &0xcd,&0x0c,&0x13,&0xec,&0x5f,&0x97,&0x44,&0x17,&0xc4,&0xa7,&0x7e,&0x3d,&0x64,&0x5d,&0x19,&0x73,
                                        &0x60,&0x81,&0x4f,&0xdc,&0x22,&0x2a,&0x90,&0x88,&0x46,&0xee,&0xb8,&0x14,&0xde,&0x5e,&0x0b,&0xdb,
                                        &0xe0,&0x32,&0x3a,&0x0a,&0x49,&0x06,&0x24,&0x5c,&0xc2,&0xd3,&0xac,&0x62,&0x91,&0x95,&0xe4,&0x79,
                                        &0xe7,&0xc8,&0x37,&0x6d,&0x8d,&0xd5,&0x4e,&0xa9,&0x6c,&0x56,&0xf4,&0xea,&0x65,&0x7a,&0xae,&0x08,
                                        &0xba,&0x78,&0x25,&0x2e,&0x1c,&0xa6,&0xb4,&0xc6,&0xe8,&0xdd,&0x74,&0x1f,&0x4b,&0xbd,&0x8b,&0x8a,
                                        &0x70,&0x3e,&0xb5,&0x66,&0x48,&0x03,&0xf6,&0x0e,&0x61,&0x35,&0x57,&0xb9,&0x86,&0xc1,&0x1d,&0x9e,
                                        &0xe1,&0xf8,&0x98,&0x11,&0x69,&0xd9,&0x8e,&0x94,&0x9b,&0x1e,&0x87,&0xe9,&0xce,&0x55,&0x28,&0xdf,
                                        &0x8c,&0xa1,&0x89,&0x0d,&0xbf,&0xe6,&0x42,&0x68,&0x41,&0x99,&0x2d,&0x0f,&0xb0,&0x54,&0xbb,&0x16];

    pub fn new(data: Vec<u8>) -> AESBlock<DecryptedState> {
        AESBlock {
            grid: data,
            state: std::marker::PhantomData::<DecryptedState>
        }
    }
    
    ///
    /// Full encryption of a single 16 byte block.
    /// 
    /// roundkeys: A vector of 11, 13 or 15 roundkeys. Each roundkey is a vector of 16 bytes.
    /// 
    /// result: A vector of 16 bytes encrypted.
    /// 
    pub fn encrypt(&self, roundkeys: &Vec<Vec<u8>>) -> AESBlock<EncryptedState> {
        let mut result = self.add_roundkey(&self.grid, &roundkeys[0]);
        for (idx, _) in roundkeys.iter().skip(1).enumerate() {
            result = self.sub_bytes(&result);
            result = self.shift_grid(&result);
            result = if idx != (roundkeys.len() - 1) {
                self.mix_columns(&result)
            } else {
                result
            };
            result = self.add_roundkey(&result, &roundkeys[idx + 1]);
        }
        AESBlock {
            grid: result.clone(),
            state: std::marker::PhantomData::<EncryptedState>
        }
    }

    ///
    /// Shifts the grid by the following pattern:
    /// row 1 not shifted.
    /// row 2 shifted to the left once
    /// row 3 shifted to the left twice
    /// row 4 shifted to the left three times
    /// 
    /// data: A vector of 16 bytes. These are considered to be in 
    ///       pattern of a 4x4 grid with row-major order.
    /// 
    /// result: A vector of 16 bytes. These are considered to be in
    ///         pattern of a 4x4 grid with row-major order.
    /// 
    fn shift_grid(&self, data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; data.len()];
        data.chunks(4).enumerate().for_each(|(idx, row)| {
            let shifted_row = self.shift_row(row, &idx);
            result.splice(idx * 4..idx * 4 + 4, shifted_row);
        });
        result
    }

    ///
    /// Mixes the columns of the grid by using the  Rijndael MixColumns
    /// algorithm. Description of the algorithm can be found here:
    /// https://en.wikipedia.org/wiki/Rijndael_MixColumns
    /// 
    /// data: A vector of 4 bytes for colunm X,
    /// 
    /// result: A vector of 4 bytes for each row.
    ///  
    fn mix_column(&self, data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0;4];
        let mut a: Vec<u8> = vec![0;4];
        let mut b: Vec<u8> = vec![0;4];
        let mut h: u8;
        for c in 0..4 {
            a[c] = data[c];
            h = (data[c] >> 7) & 1; 
            b[c] = data[c] << 1; 
            b[c] ^= h * 0x1B; 
        }
        result[0] = self.multiply(0x02, a[0]) ^ self.multiply(0x03, a[1]) ^ self.multiply(0x01, a[2]) ^ self.multiply(0x01, a[3]);
        result[1] = self.multiply(0x01, a[0]) ^ self.multiply(0x02, a[1]) ^ self.multiply(0x03, a[2]) ^ self.multiply(0x01, a[3]);
        result[2] = self.multiply(0x01, a[0]) ^ self.multiply(0x01, a[1]) ^ self.multiply(0x02, a[2]) ^ self.multiply(0x03, a[3]);
        result[3] = self.multiply(0x03, a[0]) ^ self.multiply(0x01, a[1]) ^ self.multiply(0x01, a[2]) ^ self.multiply(0x02, a[3]);   
        result
    }

    ///
    /// Mixes the columns of the grid by using the  Rijndael MixColumns
    /// algorithm. Description of the algorithm can be found here:
    /// https://en.wikipedia.org/wiki/Rijndael_MixColumns.
    /// 
    /// data: A vector of 16 bytes. These are considered to be in
    ///      pattern of a 4x4 grid with row-major order.
    /// 
    /// result: A vector of 16 bytes. These are considered to be in
    ///     pattern of a 4x4 grid with row-major order.
    /// 
    fn mix_columns(&self, data: &[u8]) -> Vec<u8> {        
        let col1: Vec<u8> = self.mix_column(&[data[0], data[4], data[8], data[12]]);
        let col2: Vec<u8> = self.mix_column(&[data[1], data[5], data[9], data[13]]);
        let col3: Vec<u8> = self.mix_column(&[data[2], data[6], data[10], data[14]]);
        let col4: Vec<u8> = self.mix_column(&[data[3], data[7], data[11], data[15]]);
        vec![col1[0], col2[0], col3[0], col4[0], col1[1], col2[1], col3[1], col4[1], col1[2], col2[2], col3[2], col4[2], col1[3], col2[3], col3[3], col4[3]]
    }

    ///
    /// Substitutes each byte in the data with the corresponding byte in the s_box.
    /// 
    /// data: A vector of bytes to be exchanged..
    /// s_box: A vector of bytes containg the substitution values.
    /// 
    /// result: A vector of bytes with the substituted values.
    /// 
    fn sub_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut result = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = *AESBlock::S_BOX[*value as usize];            
        }
        result
    }


}

///
/// Implementation of the encrypted AESBlock struct.
///
impl AESBlock<EncryptedState> {

    ///
    /// Substitutes each byte in the data with the corresponding byte in the inverse_s_box.
    /// 
    const INVERSE_S_BOX: [&'static u8; 256] = [ &0x52,&0x09,&0x6a,&0xd5,&0x30,&0x36,&0xa5,&0x38,&0xbf,&0x40,&0xa3,&0x9e,&0x81,&0xf3,&0xd7,&0xfb,
                                                &0x7c,&0xe3,&0x39,&0x82,&0x9b,&0x2f,&0xff,&0x87,&0x34,&0x8e,&0x43,&0x44,&0xc4,&0xde,&0xe9,&0xcb,
                                                &0x54,&0x7b,&0x94,&0x32,&0xa6,&0xc2,&0x23,&0x3d,&0xee,&0x4c,&0x95,&0x0b,&0x42,&0xfa,&0xc3,&0x4e,
                                                &0x08,&0x2e,&0xa1,&0x66,&0x28,&0xd9,&0x24,&0xb2,&0x76,&0x5b,&0xa2,&0x49,&0x6d,&0x8b,&0xd1,&0x25,
                                                &0x72,&0xf8,&0xf6,&0x64,&0x86,&0x68,&0x98,&0x16,&0xd4,&0xa4,&0x5c,&0xcc,&0x5d,&0x65,&0xb6,&0x92,
                                                &0x6c,&0x70,&0x48,&0x50,&0xfd,&0xed,&0xb9,&0xda,&0x5e,&0x15,&0x46,&0x57,&0xa7,&0x8d,&0x9d,&0x84,
                                                &0x90,&0xd8,&0xab,&0x00,&0x8c,&0xbc,&0xd3,&0x0a,&0xf7,&0xe4,&0x58,&0x05,&0xb8,&0xb3,&0x45,&0x06,
                                                &0xd0,&0x2c,&0x1e,&0x8f,&0xca,&0x3f,&0x0f,&0x02,&0xc1,&0xaf,&0xbd,&0x03,&0x01,&0x13,&0x8a,&0x6b,
                                                &0x3a,&0x91,&0x11,&0x41,&0x4f,&0x67,&0xdc,&0xea,&0x97,&0xf2,&0xcf,&0xce,&0xf0,&0xb4,&0xe6,&0x73,
                                                &0x96,&0xac,&0x74,&0x22,&0xe7,&0xad,&0x35,&0x85,&0xe2,&0xf9,&0x37,&0xe8,&0x1c,&0x75,&0xdf,&0x6e,
                                                &0x47,&0xf1,&0x1a,&0x71,&0x1d,&0x29,&0xc5,&0x89,&0x6f,&0xb7,&0x62,&0x0e,&0xaa,&0x18,&0xbe,&0x1b,
                                                &0xfc,&0x56,&0x3e,&0x4b,&0xc6,&0xd2,&0x79,&0x20,&0x9a,&0xdb,&0xc0,&0xfe,&0x78,&0xcd,&0x5a,&0xf4,
                                                &0x1f,&0xdd,&0xa8,&0x33,&0x88,&0x07,&0xc7,&0x31,&0xb1,&0x12,&0x10,&0x59,&0x27,&0x80,&0xec,&0x5f,
                                                &0x60,&0x51,&0x7f,&0xa9,&0x19,&0xb5,&0x4a,&0x0d,&0x2d,&0xe5,&0x7a,&0x9f,&0x93,&0xc9,&0x9c,&0xef,
                                                &0xa0,&0xe0,&0x3b,&0x4d,&0xae,&0x2a,&0xf5,&0xb0,&0xc8,&0xeb,&0xbb,&0x3c,&0x83,&0x53,&0x99,&0x61,
                                                &0x17,&0x2b,&0x04,&0x7e,&0xba,&0x77,&0xd6,&0x26,&0xe1,&0x69,&0x14,&0x63,&0x55,&0x21,&0x0c,&0x7d];

    ///
    /// Creates a new AESBlock struct with the specified data.
    /// 
    /// data: A vector of bytes.
    /// 
    /// result: A AESBlock struct with the specified data.
    ///                                                     
    pub fn new(data: Vec<u8>) -> AESBlock<EncryptedState> {
        AESBlock {
            grid: data,
            state: std::marker::PhantomData::<EncryptedState>
        }
    }

    ///
    /// Full decryption of a single 16 byte block.
    /// 
    /// roundkeys: A vector of 11, 13 or 15 roundkeys. Each roundkey is a vector of 16 bytes.
    /// 
    /// result: A vector of 16 bytes decrypted.
    /// 
    pub fn decrypt(&self, roundkeys: &Vec<Vec<u8>>) -> AESBlock<DecryptedState> {
        let mut result = self.add_roundkey(&self.grid, &roundkeys[roundkeys.len() - 1]);
        for (idx, _) in roundkeys.iter().rev().skip(1).enumerate() {
            result = if idx != (roundkeys.len() - 1) {
                self.mix_columns(&result)
            } else {
                result
            };            
            result = self.shift_grid(&result);
            result = self.sub_bytes(&result);
            result = self.add_roundkey(&result, &roundkeys[roundkeys.len() - idx - 2]);
        }        
        AESBlock {
            grid: result.clone(),
            state: std::marker::PhantomData::<DecryptedState>
        }
    }

    ///
    /// Inverse mixes the columns of the grid by using the  Rijndael MixColumns
    /// algorithm. Description of the algorithm can be found here:
    /// https://en.wikipedia.org/wiki/Rijndael_MixColumns.
    /// 
    /// data: A vector of 16 bytes. These are considered to be in
    ///      pattern of a 4x4 grid with row-major order.
    /// 
    /// result: A vector of 16 bytes. These are considered to be in
    ///     pattern of a 4x4 grid with row-major order.
    /// 
    fn mix_column(&self, data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0;4];
        let mut a: Vec<u8> = vec![0;4];
        let mut b: Vec<u8> = vec![0;4];
        let mut h: u8;
        for c in 0..4 {
            a[c] = data[c];
            h = (data[c] >> 7) & 1; 
            b[c] = data[c] << 1; 
            b[c] ^= h * 0x1B; 
        }
        result[0] = self.multiply(0x0E, a[0]) ^ self.multiply(0x0B, a[1]) ^ self.multiply(0x0D, a[2]) ^ self.multiply(0x09, a[3]);
        result[1] = self.multiply(0x09, a[0]) ^ self.multiply(0x0E, a[1]) ^ self.multiply(0x0B, a[2]) ^ self.multiply(0x0D, a[3]);
        result[2] = self.multiply(0x0D, a[0]) ^ self.multiply(0x09, a[1]) ^ self.multiply(0x0E, a[2]) ^ self.multiply(0x0B, a[3]);
        result[3] = self.multiply(0x0B, a[0]) ^ self.multiply(0x0D, a[1]) ^ self.multiply(0x09, a[2]) ^ self.multiply(0x0E, a[3]);    
        result
    }


    ///
    /// Inverses the column mixing of the grid by using the  Rijndael MixColumns
    /// algorithm. Description of the algorithm can be found here:
    /// https://en.wikipedia.org/wiki/Rijndael_MixColumns.
    /// 
    /// data: A vector of 16 bytes. These are considered to be in
    ///      pattern of a 4x4 grid with row-major order.
    /// 
    /// result: A vector of 16 bytes. These are considered to be in
    ///     pattern of a 4x4 grid with row-major order.
    /// 
    fn mix_columns(&self, data: &[u8]) -> Vec<u8> {
        let col1: Vec<u8> = self.mix_column(&[data[0], data[4], data[8], data[12]]);
        let col2: Vec<u8> = self.mix_column(&[data[1], data[5], data[9], data[13]]);
        let col3: Vec<u8> = self.mix_column(&[data[2], data[6], data[10], data[14]]);
        let col4: Vec<u8> = self.mix_column(&[data[3], data[7], data[11], data[15]]);
        vec![col1[0], col2[0], col3[0], col4[0], col1[1], col2[1], col3[1], col4[1], col1[2], col2[2], col3[2], col4[2], col1[3], col2[3], col3[3], col4[3]]
    }

    ///
    /// Shifts the grid by the following pattern:
    /// row 1 not shifted.
    /// row 2 shifted to the left thrice
    /// row 3 shifted to the left twice
    /// row 4 shifted to the left once
    /// 
    /// data: A vector of 16 bytes. These are considered to be in 
    ///       pattern of a 4x4 grid with row-major order.
    /// 
    /// result: A vector of 16 bytes. These are considered to be in
    ///         pattern of a 4x4 grid with row-major order.
    /// 
    fn shift_grid(&self, data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; data.len()];
        data.chunks(4).enumerate().for_each(|(idx, row)| {
            let shifted_row = self.shift_row(row,  &(4 - idx));
            result.splice(idx * 4..idx * 4 + 4, shifted_row);
        });
        result
    }

    ///
    /// Substitutes each byte in the data with the corresponding byte in the inverse_s_box.
    /// 
    /// data: A vector of bytes to be exchanged..
    /// s_box: A vector of bytes containg the substitution values.
    /// 
    /// result: A vector of bytes with the substituted values.
    /// 
    fn sub_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut result = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = *AESBlock::INVERSE_S_BOX[*value as usize];            
        }
        result
    }

    
}

impl<State> AESBlock<State> {

    ///
    /// Multiplies two bytes in the Galois field.
    /// 
    /// a: A byte to be multiplied.
    /// b: A byte to be multiplied.
    /// 
    /// result A byte with the result of the multiplication.
    /// 
    pub fn multiply(&self,a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut result: u8 = 0;
        let mut temp: u8;
        while b > 0 {
            if (b & 1) > 0 {
                result ^= a;
            }
            temp = a & 0x80;
            a <<= 1;
            if temp > 0 {
                a ^= 0x1B;  // Rijndael's Galois field
            }
            b >>= 1;
        }
        result
    }

    ///
    /// Shifts a row of bytes left by the specified amount.
    /// 
    /// row: A vector of 4 bytes.
    /// shift: The amount to shift the row by.
    /// 
    /// result: A vector of 4 bytes shifted.
    /// 
    /// 
    fn shift_row(&self, row: &[u8], shift: &usize) -> Vec<u8> {
        let mut result = vec![0; row.len()];
        for (idx, value) in row.iter().enumerate() {
            let new_idx = idx + row.len() - shift;
            result[(new_idx) % row.len()] = *value;
        }
        result
    }

    ///
    /// Adds the roundkey to the data.
    /// 
    /// data: A vector of bytes to be exchanged.
    /// roundkey: Key to be added to the data.
    /// 
    /// result: A vector of bytes with the added values.
    /// 
    fn add_roundkey(&self, data: &[u8], roundkey: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = value ^ roundkey[idx];
        }
        result
    }


}

impl AESData<DecryptedState> {

    ///
    /// Creates a new AESData struct with the specified data.
    /// 
    /// data: A vector of bytes.
    /// 
    /// result: A AESData struct with the specified data.
    /// 
    pub fn new(data: Vec<u8>) -> AESData<DecryptedState> {
        AESData {
            data,
            state: std::marker::PhantomData::<DecryptedState>
        }
    }

    ///
    /// Encrypts the data using AES ithe specified roundkeys.
    /// Data is padded with a character to make it a multiple of 16 bytes. 
    /// This character is the last character xored with 0x01.
    /// 
    /// roundkeys: A vector of 11, 13 or 15 roundkeys. Each roundkey is a vector of 16 bytes.
    /// 
    /// result: A vector of bytes encrypted.
    /// 
    pub fn encrypt(&self, roundkeys: &Vec<Vec<u8>>) -> AESData<EncryptedState> {
        let padding_char = self.data[self.data.len() - 1] ^ 0x01;
        let padded_data: Vec<u8> = self.data.iter().chain(vec![padding_char; 32 - (self.data.len() % 16)].iter()).cloned().collect();
        let encrypted_data = padded_data
        .chunks(16)
        .flat_map(|block: &[u8]| {
            let block = if block.len() < 16 {
                let mut block: Vec<u8> = block.to_vec();                
                block.resize(16, padding_char);
                block
            } else {
                block.to_vec()
            };
            let aes_block = AESBlock::<DecryptedState>::new(block);
            aes_block.encrypt(roundkeys).grid
        }).collect();
        AESData {
            data: encrypted_data,
            state: std::marker::PhantomData::<EncryptedState>
        }
    }
}

impl AESData<EncryptedState> {

    pub fn new(data: Vec<u8>) -> AESData<EncryptedState> {
        AESData {
            data,
            state: std::marker::PhantomData::<EncryptedState>
        }
    }

    ///
    /// Decrypts the data using AES ithe specified roundkeys.
    /// Any padded characters are removed.
    /// 
    /// roundkeys: A vector of 11, 13 or 15 roundkeys. Each roundkey is a vector of 16 bytes.
    /// 
    /// result: A vector of bytes decrypted.
    /// 
    pub fn decrypt(&self, roundkeys: &Vec<Vec<u8>>) -> AESData<DecryptedState> {
        let decrypted_data: Vec<u8> = self.data
        .chunks(16)
        .flat_map(|block| {
            let aes_block = AESBlock::<EncryptedState>::new(block.to_vec());
            aes_block.decrypt(roundkeys).grid
        })
        .collect();
        let padded_char: u8 = decrypted_data[decrypted_data.len() - 1];
        let idx = decrypted_data.iter().rev().position(|&x| x != padded_char).unwrap_or(0);                
        AESData {
            data: decrypted_data[..decrypted_data.len() - idx].to_vec(),
            state: std::marker::PhantomData::<DecryptedState>
        }
    }
}

impl<State> AESData<State> {
    
    const R_CON: &[u8] = &[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    ///
    /// Generates the roundkeys from the key.
    /// 
    /// key: A vector of bytes used to generate the roundkeys.
    /// 
    /// result: A vector of roundkeys. Each roundkey is a vector of 16 bytes.
    /// 
    pub fn generate_roundkeys(key: &[u8]) -> Vec<Vec<u8>> {
        let mut roundkeys: Vec<Vec<u8>> = vec![key.to_vec()];
        let mut roundkey: Vec<u8> = key.to_vec();
        for idx in 0..10 {
            roundkey = AESData::<State>::generate_roundkey(&roundkey, idx);
            roundkeys.push(roundkey.clone());
        }
        roundkeys
    }

    ///
    /// Generates a roundkey from the previous roundkey.
    /// 
    /// roundkey: A vector of bytes to be exchanged.
    /// iteration: The iteration of the roundkey.
    /// 
    /// result: A vector of with new roundkey.
    /// 
    fn generate_roundkey(roundkey: &Vec<u8>, iteration: usize) -> Vec<u8> { 
        let mut result: Vec<u8> = vec![0; roundkey.len()];
        let mut temp: Vec<u8> = vec![0; 4];
        temp[..4].copy_from_slice(&roundkey[12..16]);
        temp = AESData::<State>::rotate(&temp);
        temp = AESData::<State>::sub_word(&temp);
        temp[0] ^= AESData::<State>::R_CON[iteration];
        for i in 0..4 {
            temp[i] ^= roundkey[i];
        }
        result[..4].copy_from_slice(&temp[..4]);
        for i in 4..16 {
            result[i] = result[i - 4] ^ roundkey[i];
        }
        result
    }

    ///
    /// Rotates the bytes in the word.
    /// 
    /// word: A vector of bytes to be rotated.
    /// 
    /// result: A vector of bytes with the rotated values.
    /// 
    fn rotate(word: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; word.len()];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        result
    }

    ///
    /// Substitutes each byte in the data with the corresponding byte in the s_box.
    /// This is the same substitution as in the sub_bytes function, but it is used
    /// for generating the roundkeys.
    /// 
    /// word: A vector of bytes to be exchanged..
    /// 
    /// result: A vector of bytes with the substituted values.
    /// 
    fn sub_word(word: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; word.len()];
        for i in 0..4 {            
            result[i] = *AESBlock::S_BOX[word[i] as usize]
        }
        result
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_add_roundkey() {
        let aes_block = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![0, 3, 6, 11, 8, 4, 5, 2, 15, 0, 1, 6, 3, 15, 13, 11];
        let roundkey: Vec<u8> = vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = aes_block.add_roundkey(&grid, &roundkey);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row0() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 2, 3, 4];
        let row: Vec<u8> = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &0);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row1() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![2, 3, 4, 1];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &1);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row2() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![3, 4, 1, 2];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &2);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row3() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![4, 1, 2, 3];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &3);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_grid() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = aes_block.shift_grid(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_grid_reverse() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
        let result: Vec<u8> = aes_block.shift_grid(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_column() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 1, 1, 1];
        let data: &[u8] = &[1, 1, 1, 1];
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_inverse_mix_column() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 1, 1, 1];
        let data: &[u8] = &[1, 1, 1, 1];
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_column2() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![142, 77, 161, 188];
        let data: &[u8] = &[219, 19, 83, 69];        
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_inverse_mix_column2() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![219, 19, 83, 69];
        let data: &[u8] = &[142, 77, 161, 188];
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_column3() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![159, 220, 88, 157];
        let data: &[u8] = &[242, 10, 34, 92];
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_inverse_mix_column3() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![242, 10, 34, 92];
        let data: &[u8] = &[159, 220, 88, 157];
        let result: Vec<u8> = aes_block.mix_column(data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_columns() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let grid: Vec<u8> = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let result: Vec<u8> = aes_block.mix_columns(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_inverse_mix_columns() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let grid: Vec<u8> = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let result: Vec<u8> = aes_block.mix_columns(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_columns2() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![142, 159, 1, 198, 77, 220, 1, 198, 161, 88, 1, 198, 188, 157, 1, 198];
        let grid: Vec<u8> = vec![219, 242, 1, 198, 19, 10, 1, 198, 83, 34, 1, 198, 69, 92, 1, 198];
        let result: Vec<u8> = aes_block.mix_columns(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_inverse_mix_columns2() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![219, 242, 1, 198, 19, 10, 1, 198, 83, 34, 1, 198, 69, 92, 1, 198];
        let grid: Vec<u8> = vec![142, 159, 1, 198, 77, 220, 1, 198, 161, 88, 1, 198, 188, 157, 1, 198];
        let result: Vec<u8> = aes_block.mix_columns(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_sub_bytes() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![185, 137, 124, 180, 125, 103, 124, 180, 237, 147, 124, 180, 110, 74, 124, 180];
        let grid: Vec<u8> = vec![219, 242, 1, 198, 19, 10, 1, 198, 83, 34, 1, 198, 69, 92, 1, 198];
        let result: Vec<u8> = aes_block.sub_bytes(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_sub_bytes_inverse() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![219, 242, 1, 198, 19, 10, 1, 198, 83, 34, 1, 198, 69, 92, 1, 198];
        let grid: Vec<u8> = vec![185, 137, 124, 180, 125, 103, 124, 180, 237, 147, 124, 180, 110, 74, 124, 180];
        let result: Vec<u8> = aes_block.sub_bytes(&grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_encrypt() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let roundkeys: Vec<Vec<u8>> = vec![
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4]
            ];
        let result: AESBlock<EncryptedState> = aes_block.encrypt(&roundkeys);
        let expected_result: Vec<u8> = vec![128, 249, 176, 188, 201, 213, 195, 110, 192, 161, 230, 165, 31, 182, 33, 44];
        assert_eq!(expected_result, result.grid);
    }

    #[test]
    fn test_decrypt() {
        let aes_block: AESBlock<EncryptedState> = AESBlock::<EncryptedState>::new(vec![128, 249, 176, 188, 201, 213, 195, 110, 192, 161, 230, 165, 31, 182, 33, 44]);
        let roundkeys: Vec<Vec<u8>> = vec![
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4]
            ];
        let result: AESBlock<DecryptedState> = aes_block.decrypt(&roundkeys);
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(expected_result, result.grid);
    }

    #[test]
    fn encrypt_decrypt_file() {
        let bytes = &std::fs::read("testdata/testfile.in").unwrap();   
        let expected_result = String::from_utf8_lossy(bytes);     
        let roundkeys: Vec<Vec<u8>> = vec![
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4] 
            ];      
        let aes_data = AESData::<DecryptedState>::new(bytes.to_vec());
        let encrypted = aes_data.encrypt(&roundkeys);
        let decrypted = encrypted.decrypt(&roundkeys);
        let result = String::from_utf8_lossy(&decrypted.data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn encrypt_decrypt_file2() {
        let bytes = &std::fs::read("testdata/large.in").unwrap();   
        let expected_result = String::from_utf8_lossy(bytes);     
        let roundkeys: Vec<Vec<u8>> = vec![
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![1, 3, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![2, 4, 4, 8, 12, 1, 3, 5, 7, 9, 11, 113, 15, 2, 3, 4], 
            vec![3, 5, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![4, 6, 4, 8, 12, 1, 3, 5, 7, 9, 11, 123, 15, 2, 3, 4],
            vec![5, 7, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![6, 8, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![7, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 123, 15, 2, 3, 4], 
            vec![8, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![9, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 143, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4] 
            ];      
        let aes_data = AESData::<DecryptedState>::new(bytes.to_vec());
        let encrypted = aes_data.encrypt(&roundkeys);
        let decrypted = encrypted.decrypt(&roundkeys);
        let result = String::from_utf8_lossy(&decrypted.data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn encrypt_decrypt_file3() {
        let bytes = &std::fs::read("testdata/binary.in").unwrap();   
        let expected_result = String::from_utf8_lossy(bytes);     
        let roundkeys: Vec<Vec<u8>> = vec![
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![1, 3, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![2, 4, 4, 8, 12, 1, 3, 5, 7, 9, 11, 113, 15, 2, 3, 4], 
            vec![3, 5, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![4, 6, 4, 8, 12, 1, 3, 5, 7, 9, 11, 123, 15, 2, 3, 4],
            vec![5, 7, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![6, 8, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![7, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 123, 15, 2, 3, 4], 
            vec![8, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], 
            vec![9, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 143, 15, 2, 3, 4],
            vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4] 
            ];      
        let aes_data = AESData::<DecryptedState>::new(bytes.to_vec());
        let encrypted = aes_data.encrypt(&roundkeys);
        let decrypted = encrypted.decrypt(&roundkeys);
        let result = String::from_utf8_lossy(&decrypted.data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn generate_roundkeys() {
        let init_key: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let roundkeys = AESData::<EncryptedState>::generate_roundkeys(&init_key);
        let expected_result: Vec<Vec<u8>> = vec![
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63],
            vec![0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa],
            vec![0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99],
            vec![0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81, 0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b],
            vec![0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90],
            vec![0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37, 0x6a, 0xb4, 0x9b, 0xa7],
            vec![0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b, 0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b],
            vec![0x0e, 0xf9, 0x03, 0x33, 0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f],
            vec![0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66, 0x49, 0x41],
            vec![0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e]
            ];
        assert_eq!(expected_result, roundkeys);
    }

}







