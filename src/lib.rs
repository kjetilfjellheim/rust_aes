use std::vec::Vec;

pub struct DecryptedState;
pub struct EncryptedState;

pub struct AESBlock<State = DecryptedState> {
    grid: Vec<u8>,
    state: std::marker::PhantomData<State>
}

impl AESBlock {

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

    fn shift_row(&self, row: &[u8], shift: &usize) -> Vec<u8> {
        let mut result = vec![0; row.len()];
        for (idx, value) in row.iter().enumerate() {
            let new_idx = idx + row.len() - shift;
            result[(new_idx) % row.len()] = *value;
        }
        result
    }

    fn shift_grid(&self, data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; data.len()];
        data.chunks(4).enumerate().for_each(|(idx, row)| {
            let shifted_row = self.shift_row(row, &idx);
            result.splice(idx * 4..idx * 4 + 4, shifted_row);
        });
        result
    }

    fn mix_columns(&self, data: &[u8]) -> Vec<u8> {
        data.to_owned()
    }

   fn add_roundkey(&self, data: &[u8], roundkey: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = value ^ roundkey[idx];
        }
        result
    }

    fn sub_bytes(&self, data: &[u8], s_box: &[u8]) -> Vec<u8> {
        let mut result = vec![0; data.len()];
        for (idx, value) in data.iter().enumerate() {
            result[idx] = s_box[*value as usize];
        }
        result
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_add_roundkey() {
        let aes_block = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![0, 3, 6, 11, 8, 4, 5, 2, 15, 0, 1, 6, 3, 15, 13, 11];
        let roundkey: Vec<u8> = vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = aes_block.add_roundkey(&grid, &roundkey);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row0() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![1, 2, 3, 4];
        let row: Vec<u8> = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &0);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row1() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![2, 3, 4, 1];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &1);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row2() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![3, 4, 1, 2];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &2);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row3() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result = vec![4, 1, 2, 3];
        let row = vec![1, 2, 3, 4];
        let result = aes_block.shift_row(&row, &3);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_grid() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = aes_block.shift_grid(&grid);
        println!("{:?}", result);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_encrypt() {
        let aes_block: AESBlock = AESBlock::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let roundkeys: Vec<Vec<u8>> = vec![vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4], vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4]];
        let result: AESBlock<EncryptedState> = aes_block.encrypt(&roundkeys, &gen_s_box());
    }


    fn gen_s_box() -> Vec<u8> {
        (0..255).collect()
    }


}
