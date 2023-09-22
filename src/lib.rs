use std::vec::Vec;

fn add_roundkey(grid: Vec<u8>, roundkey: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; grid.len()];
    for (idx, value) in grid.iter().enumerate() {
        result[idx] = value ^ roundkey[idx];
    }
    result
}

fn shift_row(row: Vec<u8>, shift: usize) -> Vec<u8> {
    let mut result = vec![0; row.len()];
    for (idx, value) in row.iter().enumerate() {
        let new_idx = idx + row.len() - shift;
        result[(new_idx) % row.len()] = *value;
    }
    result
}

fn shift_grid(grid: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; grid.len()];
    grid.chunks(4).enumerate().for_each(|(idx, row)| {
        let shifted_row = shift_row(row.to_vec(), idx);
        result.splice(idx * 4..idx * 4 + 4, shifted_row);
    });
    result
}

fn shift_grid_reverse(grid: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; grid.len()];
    grid.chunks(4).enumerate().for_each(|(idx, row)| {
        let shifted_row = shift_row(row.to_vec(), 4 - idx );
        result.splice(idx * 4..idx * 4 + 4, shifted_row);
    });
    result
}

fn mix_column(column: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; column.len()];
    result[0] = column[0] ^ column[1] ^ column[2] ^ column[3];
    result[1] = column[0] ^ column[1] ^ column[2] ^ column[3];
    result[2] = column[0] ^ column[1] ^ column[2] ^ column[3];
    result[3] = column[0] ^ column[1] ^ column[2] ^ column[3];
    result    
}

fn mix_columns(grid: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; grid.len()];
    let mixed_column1 = mix_column(vec![grid[0], grid[4], grid[8], grid[12]]);
    let mixed_column2 = mix_column(vec![grid[1], grid[5], grid[9], grid[13]]);
    let mixed_column3 = mix_column(vec![grid[2], grid[6], grid[10], grid[14]]);
    let mixed_column4 = mix_column(vec![grid[3], grid[7], grid[11], grid[15]]);
    vec![mixed_column1[0], mixed_column2[0], mixed_column3[0], mixed_column4[0],
         mixed_column1[1], mixed_column2[1], mixed_column3[1], mixed_column4[1],
         mixed_column1[2], mixed_column2[2], mixed_column3[2], mixed_column4[2],
         mixed_column1[3], mixed_column2[3], mixed_column3[3], mixed_column4[3]]
}


#[cfg(test)]
mod tests {

    use super::*;   

    #[test]
    fn test_add_roundkey() {
        let expected_result: Vec<u8> = vec![0, 3, 6, 11, 8, 4, 5, 2, 15, 0, 1, 6, 3, 15, 13, 11];
        let roundkey:Vec<u8>  = vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = add_roundkey(grid, roundkey);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_add_roundkey_reverse() {
        let expected_result: Vec<u8> = vec![00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let roundkey:Vec<u8>  = vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4];
        let grid: Vec<u8> = vec![0, 3, 6, 11, 8, 4, 5, 2, 15, 0, 1, 6, 3, 15, 13, 11];
        let result: Vec<u8> = add_roundkey(grid, roundkey);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row0() {
        let expected_result: Vec<u8> = vec![1, 2, 3, 4];
        let row: Vec<u8> = vec![1, 2, 3, 4];
        let result = shift_row(row, 0);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row0_reverse() {
        let expected_result: Vec<u8> = vec![1, 2, 3, 4];
        let row: Vec<u8> = vec![1, 2, 3, 4];
        let result = shift_row(row, 0);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row1() {
        let expected_result = vec![2, 3, 4, 1];
        let row = vec![1, 2, 3, 4];
        let result = shift_row(row, 1);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row1_reverse() {
        let expected_result = vec![1, 2, 3, 4];
        let row = vec![2, 3, 4, 1];
        let result = shift_row(row, 3);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row2() {
        let expected_result = vec![3, 4, 1, 2];
        let row = vec![1, 2, 3, 4];
        let result = shift_row(row, 2);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row2_reverse() {
        let expected_result = vec![1, 2, 3, 4];
        let row = vec![3, 4, 1, 2];
        let result = shift_row(row, 2);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row3() {
        let expected_result = vec![4, 1, 2, 3];
        let row = vec![1, 2, 3, 4];
        let result = shift_row(row, 3);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_row3_reverse() {
        let expected_result = vec![1, 2, 3, 4];
        let row = vec![4, 1, 2, 3];
        let result = shift_row(row, 1);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_shift_grid() {
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let result: Vec<u8> = shift_grid(grid);
        println!("{:?}",result);
        assert_eq!(expected_result, result);        
    }

    #[test]
    fn test_shift_grid_reverse() {
        let expected_result: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let grid: Vec<u8> = vec![0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14];
        let result: Vec<u8> = shift_grid_reverse(grid);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_full_encrypt_round1() {
        let grid: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let roundkey:Vec<u8>  = vec![0, 2, 4, 8, 12, 1, 3, 5, 7, 9, 11, 13, 15, 2, 3, 4];
        let grid: Vec<u8> = add_roundkey(grid, roundkey);
        let grid: Vec<u8> = shift_grid(grid);
        let grid = mix_columns(grid);
        println!("{:?}",grid);
    }

    


}
