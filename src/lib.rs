use std::vec::Vec;

pub struct DecryptedState;
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
/// Implementation of the decrypted AESBlock struct.
///
impl AESBlock<DecryptedState> {

    const S_BOX: [&'static u8; 256] = [ &0x63,&0x7c,&0x77,&0x7b,&0xf2,&0x6b,&0x6f,&0xc5,&0x30,&0x01,&0x67,&0x2b,&0xfe,&0xd7,&0xab,&0x76,
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
            result = if idx != roundkeys.len() - 1 {
                self.mix_columns(&result)
            } else {
                result
            };
            result = self.add_roundkey(&result, &roundkeys[idx]);
        }
        AESBlock {
            grid: result.clone(),
            state: std::marker::PhantomData::<EncryptedState>
        }
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
    fn mix_column(&self, data: &Vec<&u8>) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0;4];
        let mut a: Vec<u8> = vec![0;4];
        let mut b: Vec<u8> = vec![0;4];
        let mut h: u8;
        for c in 0..4 {
            a[c] = *data[c];
            h = (data[c] >> 7) & 1; 
            b[c] = data[c] << 1; 
            b[c] ^= h * 0x1B; 
        }
        result[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
        result[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
        result[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
        result[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
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
        let col1: Vec<u8> = self.mix_column(&data.iter().step_by(4).collect());
        let col2: Vec<u8> = self.mix_column(&data.iter().skip(1).step_by(4).collect());
        let col3: Vec<u8> = self.mix_column(&data.iter().skip(2).step_by(4).collect());
        let col4: Vec<u8> = self.mix_column(&data.iter().skip(3).step_by(4).collect());
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

    pub fn new(data: Vec<u8>) -> AESBlock<EncryptedState> {
        AESBlock {
            grid: data,
            state: std::marker::PhantomData::<EncryptedState>
        }
    }

    //TODO: Implement decryption
    pub fn decrypt(&self, _: &Vec<Vec<u8>>, _: &[u8]) -> AESBlock<DecryptedState> {
        AESBlock {
            grid: self.grid.clone(),
            state: std::marker::PhantomData::<DecryptedState>
        }
    }

}

///
/// Implementation of the encrypted AESBlock struct.
///
impl AESBlock {

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
    fn test_mix_column() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 1, 1, 1];
        let data: Vec<&u8> = vec![&1, &1, &1, &1];
        let result: Vec<u8> = aes_block.mix_column(&data);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_mix_column2() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![142, 77, 161, 188];
        let data: Vec<&u8> = vec![&219, &19, &83, &69];
        let result: Vec<u8> = aes_block.mix_column(&data);
        assert_eq!(expected_result, result);
    }


    #[test]
    fn test_mix_column3() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![159, 220, 88, 157];
        let data: Vec<&u8> = vec![&242, &10, &34, &92];
        let result: Vec<u8> = aes_block.mix_column(&data);
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
    fn test_mix_columns2() {
        let aes_block: AESBlock = AESBlock::<DecryptedState>::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![142, 159, 1, 198, 77, 220, 1, 198, 161, 88, 1, 198, 188, 157, 1, 198];
        let grid: Vec<u8> = vec![219, 242, 1, 198, 19, 10, 1, 198, 83, 34, 1, 198, 69, 92, 1, 198];
        let result: Vec<u8> = aes_block.mix_columns(&grid);
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

}
