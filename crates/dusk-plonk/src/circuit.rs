use dusk_plonk::prelude::*;

use crate::utils::{is_eq_with_output, is_zero_with_output, range_check};

// Implements a circuit that checks if a sudoku works.
#[derive(Debug, Default)]
pub struct SudokuCircuit {
    pub unsolved: [[u64; 9]; 9],
    pub solved: [[u64; 9]; 9],
}

impl Circuit for SudokuCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let one_var = composer.append_constant(BlsScalar::one());
        // new circuit
        let unsolved_vars: Vec<Vec<Witness>> = self
            .unsolved
            .iter()
            .map(|line| {
                let u: Vec<Witness> = line
                    .iter()
                    .map(|x| {
                        let t = composer.append_public(BlsScalar::from(*x));
                        t
                    })
                    .collect();
                u
            })
            .collect();

        let solved_vars: Vec<Vec<Witness>> = self
            .solved
            .iter()
            .map(|line| {
                let u: Vec<Witness> = line
                    .iter()
                    .map(|x| {
                        let t = composer.append_witness(BlsScalar::from(*x));
                        t
                    })
                    .collect();
                u
            })
            .collect();

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        for i in 0..9 {
            for j in 0..9 {
                range_check(composer, solved_vars[i][j])
            }
        }

        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                let is_zero = is_zero_with_output(composer, unsolved_vars[i][j]);
                let is_equal = is_eq_with_output(composer, unsolved_vars[i][j], solved_vars[i][j]);
                let result = composer.component_select(is_zero, one_var, is_equal);
                composer.assert_equal_constant(result, BlsScalar::one(), None);
            }
        }

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..j {
                    let is_equal =
                        is_eq_with_output(composer, solved_vars[i][k], solved_vars[i][j]);
                    composer.assert_equal_constant(is_equal, BlsScalar::zero(), None);
                }
            }
        }

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..i {
                    let is_equal =
                        is_eq_with_output(composer, solved_vars[k][j], solved_vars[i][j]);
                    composer.assert_equal_constant(is_equal, BlsScalar::zero(), None);
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
                                let is_equal = is_eq_with_output(
                                    composer,
                                    solved_vars[m][n],
                                    solved_vars[k][l],
                                );
                                composer.assert_equal_constant(is_equal, BlsScalar::zero(), None);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use dusk_bytes::Serializable;
    use dusk_plonk::prelude::*;

    use crate::circuit::SudokuCircuit;

    #[test]
    fn circuit_with_all_gates() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let rng = &mut StdRng::seed_from_u64(8349u64);

        let n = 1 << 16;
        let label = b"demo";
        let pp = PublicParameters::setup(n, rng).expect("failed to create pp");
        println!("Public Parameters Setuped");
        let (prover, verifier) =
            Compiler::compile::<SudokuCircuit>(&pp, label).expect("failed to compile circuit");
        println!("Compiled");
        let len = prover.serialized_size();
        let prover = prover.to_bytes();

        assert_eq!(prover.len(), len);

        let prover: Prover<SudokuCircuit> =
            Prover::try_from_bytes(&prover).expect("failed to deserialize prover");

        let len = verifier.serialized_size();
        let verifier = verifier.to_bytes();

        assert_eq!(verifier.len(), len);

        let verifier: Verifier<SudokuCircuit> =
            Verifier::try_from_bytes(&verifier).expect("failed to deserialize verifier");

        let (proof, public_inputs) = prover
            .prove(
                rng,
                &SudokuCircuit {
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
                },
            )
            .expect("failed to prove");

        println!(
            "proof len: {}, public_inputs len: {}",
            proof.to_bytes().len(),
            public_inputs.len()
        );
        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }
}
