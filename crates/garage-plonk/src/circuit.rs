use std::marker::PhantomData;

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk::prelude::{Circuit, Variable};

use crate::utils::range_check;

// Implements a circuit that checks if a sudoku works.
#[derive(derivative::Derivative, Clone)]
#[derivative(Debug(bound = ""), Default(bound = ""))]
pub struct SudokuCircuit<F, P> {
    pub unsolved: [[u8; 9]; 9],
    pub solved: [[u8; 9]; 9],
    pub _marker1: PhantomData<F>,
    pub _marker2: PhantomData<P>,
}

impl<F, P> Circuit<F, P> for SudokuCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut plonk::prelude::StandardComposer<F, P>,
    ) -> Result<(), plonk::prelude::Error> {
        let one_var = composer.add_input(F::one());
        let zero_var = composer.zero_var();
        // new circuit
        let unsolved_vars: Vec<Vec<Variable>> = self
            .unsolved
            .iter()
            .map(|line| {
                let u: Vec<Variable> = line
                    .iter()
                    .map(|x| {
                        let t = composer.add_input(F::from(*x));
                        t
                    })
                    .collect();
                u
            })
            .collect();

        let solved_vars: Vec<Vec<Variable>> = self
            .solved
            .iter()
            .map(|line| {
                let u: Vec<Variable> = line
                    .iter()
                    .map(|x| {
                        let t = composer.add_input(F::from(*x));
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
                range_check(composer, solved_vars[i][j]);
            }
        }

        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                let is_zero = composer.is_zero_with_output(unsolved_vars[i][j]);
                let is_equal = composer.is_eq_with_output(unsolved_vars[i][j], solved_vars[i][j]);
                let result = composer.conditional_select(is_zero, one_var, is_equal);
                composer.assert_equal(result, one_var);
            }
        }

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..j {
                    let is_equal = composer.is_eq_with_output(solved_vars[i][k], solved_vars[i][j]);
                    composer.assert_equal(is_equal, zero_var)
                }
            }
        }

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..i {
                    let is_equal = composer.is_eq_with_output(solved_vars[k][j], solved_vars[i][j]);
                    composer.assert_equal(is_equal, zero_var)
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
                                let is_equal = composer
                                    .is_eq_with_output(solved_vars[m][n], solved_vars[k][l]);
                                composer.assert_equal(is_equal, zero_var)
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 16
    }
}

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
    use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
    use ark_poly::polynomial::univariate::DensePolynomial;
    use ark_poly_commit::{sonic_pc::SonicKZG10, PolynomialCommitment};
    use ark_serialize::CanonicalSerialize;
    use plonk::error::to_pc_error;
    use plonk::prelude::Error;
    use plonk_core::circuit::{verify_proof, Circuit};
    use plonk_core::prelude::*;
    use rand_core::OsRng;

    use crate::circuit::SudokuCircuit;

    #[test]
    fn test_circuit() -> Result<(), Error> {
        // Generate CRS
        type PC = SonicKZG10<Bls12_381, DensePolynomial<BlsScalar>>;
        let pp = PC::setup(1 << 16, None, &mut OsRng).map_err(to_pc_error::<BlsScalar, PC>)?;

        let mut circuit = SudokuCircuit::<BlsScalar, JubJubParameters>::default();
        // Compile the circuit
        let (pk_p, (vk, _pi_pos)) = circuit.compile::<PC>(&pp)?;

        // Prover POV
        let (proof, pi) = {
            let mut circuit: SudokuCircuit<BlsScalar, JubJubParameters> = SudokuCircuit {
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
                _marker1: PhantomData,
                _marker2: PhantomData,
            };

            circuit.gen_proof::<PC>(&pp, pk_p, b"Test")
        }?;

        println!("proof len: {}", proof.serialized_size(),);

        // Verifier POV
        let verifier_data = VerifierData::new(vk, pi);
        verify_proof::<BlsScalar, JubJubParameters, PC>(
            &pp,
            verifier_data.key,
            &proof,
            &verifier_data.pi,
            b"Test",
        )
    }
}
