use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::witness::{PartialWitness, Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;

use anyhow::{Ok, Result};

use crate::utils::range_check;

pub struct SudokuCircuit {
    pub unsolved: [[u64; 9]; 9],
    pub solved: [[u64; 9]; 9],
}

/**
 * prove a^2 * b^2 = c
 * |(0)    (1)      (2)          |
 * | a      a      a * a         |
 * | b      b      b * b         |
 * | a * a  b * b  a * a + b * b |
 */
impl SudokuCircuit {
    pub fn synthesize(&self) -> Result<(ProofWithPublicInputs<F, C, 2>, CircuitData<F, C, 2>)> {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, 2>::new(config);
        let unsolved_targets = [0; 9].map(|_| [0; 9].map(|_| builder.add_virtual_public_input()));
        let solved_targets = [0; 9].map(|_| [0; 9].map(|_| builder.add_virtual_target()));

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        for i in 0..9 {
            for j in 0..9 {
                range_check(&mut builder, solved_targets[i][j]);
            }
        }

        let zero_target = builder.zero();
        let one_target = builder.one();
        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                let is_zero = builder.is_equal(unsolved_targets[i][j], zero_target);
                let is_equal = builder.is_equal(unsolved_targets[i][j], solved_targets[i][j]);
                let result = builder.select(is_zero, one_target, is_equal.target);
                builder.assert_one(result);
            }
        }

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..j {
                    let is_equal = builder.is_equal(solved_targets[i][k], solved_targets[i][j]);
                    builder.assert_zero(is_equal.target);
                }
            }
        }

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..i {
                    let is_equal = builder.is_equal(solved_targets[k][j], solved_targets[i][j]);
                    builder.assert_zero(is_equal.target);
                }
            }
        }

        // Check if each square in solved has all the numbers from 1 to 9, both included
        // For each square and for each element in each square, check that the
        // element is not equal to previous elements in the same square
        for i in [0, 3, 6] {
            for j in [0, 3, 6] {
                for k in i..i + 3 {
                    for l in j..j + 3 {
                        for m in i..=k {
                            for n in j..l {
                                let is_equal =
                                    builder.is_equal(solved_targets[m][n], solved_targets[k][l]);
                                builder.assert_zero(is_equal.target);
                            }
                        }
                    }
                }
            }
        }

        // build circuit
        let circuit = builder.build();

        let mut pw = PartialWitness::new();
        for i in 0..9 {
            for j in 0..9 {
                pw.set_target(
                    unsolved_targets[i][j],
                    F::from_canonical_u64(self.unsolved[i][j]),
                );
                pw.set_target(
                    solved_targets[i][j],
                    F::from_canonical_u64(self.solved[i][j]),
                );
            }
        }
        let proof = circuit.prove(pw).unwrap();
        Ok((proof, circuit))
    }
}

#[cfg(test)]
mod tests {
    use super::SudokuCircuit;

    #[test]
    fn test_circuit() {
        let circuit = SudokuCircuit {
            unsolved: [
                [0, 0, 0, 0, 0, 6, 0, 0, 0],
                [0, 0, 7, 2, 0, 0, 8, 0, 0],
                [9, 0, 6, 8, 0, 0, 0, 1, 0],
                [3, 0, 0, 7, 0, 0, 0, 2, 9],
                [0, 0, 0, 0, 0, 0, 0, 0, 0],
                [4, 0, 0, 5, 0, 0, 0, 7, 0],
                [6, 5, 0, 1, 0, 0, 0, 0, 0],
                [8, 0, 1, 0, 5, 0, 3, 0, 0],
                [7, 9, 2, 0, 0, 0, 0, 0, 4],
            ],
            solved: [
                [1, 8, 4, 3, 7, 6, 2, 9, 5],
                [5, 3, 7, 2, 9, 1, 8, 4, 6],
                [9, 2, 6, 8, 4, 5, 7, 1, 3],
                [3, 6, 5, 7, 1, 8, 4, 2, 9],
                [2, 7, 8, 4, 6, 9, 5, 3, 1],
                [4, 1, 9, 5, 3, 2, 6, 7, 8],
                [6, 5, 3, 1, 2, 4, 9, 8, 7],
                [8, 4, 1, 9, 5, 7, 3, 6, 2],
                [7, 9, 2, 6, 8, 3, 1, 5, 4],
            ],
        };

        let (proof, data) = circuit.synthesize().unwrap();
        data.verify(proof).unwrap();
    }
}
