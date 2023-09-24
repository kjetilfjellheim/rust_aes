use std::vec::Vec;

pub struct DecryptedState;
pub struct EncryptedState;

pub struct AESBlock<State = DecryptedState> {
    grid: Vec<u8>,
    state: std::marker::PhantomData<State>
}

impl AESBlock<DecryptedState> {

    pub fn new(data: Vec<u8>) -> AESBlock<DecryptedState> {
        AESBlock {
            grid: data,
            state: std::marker::PhantomData::<DecryptedState>
        }
    }
    
    pub fn encrypt(&self, roundkeys: &Vec<Vec<u8>>, s_box: &[u8]) -> AESBlock<EncryptedState> {
        let mut result = self.add_roundkey(&self.grid, &roundkeys[0]);
        for (idx, _) in roundkeys.iter().skip(1).enumerate() {
            result = self.sub_bytes(&result, s_box);
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

    fn mix_columns(&self, data: &[u8]) -> Vec<u8> {        
        let col1: Vec<u8> = self.mix_column(&data.iter().step_by(4).collect());
        let col2: Vec<u8> = self.mix_column(&data.iter().skip(1).step_by(4).collect());
        let col3: Vec<u8> = self.mix_column(&data.iter().skip(2).step_by(4).collect());
        let col4: Vec<u8> = self.mix_column(&data.iter().skip(3).step_by(4).collect());
        vec![col1[0], col2[0], col3[0], col4[0], col1[1], col2[1], col3[1], col4[1], col1[2], col2[2], col3[2], col4[2], col1[3], col2[3], col3[3], col4[3]]
    }

}

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

impl AESBlock {

    ///
    /// Substitutes each byte in the data with the corresponding byte in the s_box.
    /// 
    /// data: A vector of bytes to be exchanged..
    /// s_box: A vector of bytes containg the substitution values.
    /// 
    /// result: A vector of bytes with the substituted values.
    /// 
    fn sub_bytes(&self, data: &[u8], s_box: &[u8]) -> Vec<u8> {
        let mut result = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = s_box[*value as usize];
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
        let roundkeys: Vec<Vec<u8>> = vec![vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4]];
        let result: AESBlock<EncryptedState> = aes_block.encrypt(&roundkeys, &gen_s_box());
    }


    fn gen_s_box() -> Vec<u8> {
        (0..255).collect()
    }


}
