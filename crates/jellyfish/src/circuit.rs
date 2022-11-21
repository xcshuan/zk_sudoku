//! This file contains an example showing how to build a proof of knowledge
//! of the exponent over a native field.
//!
//! - secret input `x`;
//! - public generator `G`;
//! - public group element `X := xG`

use std::marker::PhantomData;

use ark_ec::ModelParameters;
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

use crate::utils::range_check;

pub struct SudokuCircuit<F, P> {
    pub unsolved: [[u8; 9]; 9],
    pub solved: [[u8; 9]; 9],
    pub _marker1: PhantomData<F>,
    pub _marker2: PhantomData<P>,
}

impl<F: PrimeField, P: ModelParameters<BaseField = F>> SudokuCircuit<F, P> {
    pub fn synthesize(&self) -> Result<PlonkCircuit<F>, CircuitError> {
        // Step 1:
        // We instantiate a turbo plonk circuit.
        //
        // Here we only need turbo plonk since we are not using plookups.
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let mut unsolved_vars = Vec::with_capacity(9);
        self.unsolved.iter().enumerate().try_for_each(|(i, x)| {
            unsolved_vars.push(Vec::with_capacity(9));
            x.iter().try_for_each(|y| {
                unsolved_vars[i].push(circuit.create_variable((*y).into())?);
                <Result<(), CircuitError>>::Ok(())
            })?;
            <Result<(), CircuitError>>::Ok(())
        })?;

        let mut solved_vars = Vec::with_capacity(9);
        self.solved.iter().enumerate().try_for_each(|(i, x)| {
            solved_vars.push(Vec::with_capacity(9));
            x.iter().try_for_each(|y| {
                solved_vars[i].push(circuit.create_variable((*y).into())?);
                <Result<(), CircuitError>>::Ok(())
            })?;
            <Result<(), CircuitError>>::Ok(())
        })?;

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        for i in 0..9 {
            for j in 0..9 {
                range_check(&mut circuit, solved_vars[i][j])?;
            }
        }

        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                let is_zero = circuit.is_zero(unsolved_vars[i][j])?;
                let is_equal = circuit.is_equal(unsolved_vars[i][j], solved_vars[i][j])?;
                let result = circuit.conditional_select(is_zero, is_equal.into(), circuit.one())?;
                circuit.enforce_true(result)?;
            }
        }

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..j {
                    let is_equal = circuit.is_equal(solved_vars[i][k], solved_vars[i][j])?;
                    circuit.enforce_false(is_equal.into())?;
                }
            }
        }

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..i {
                    let is_equal = circuit.is_equal(solved_vars[k][j], solved_vars[i][j])?;
                    circuit.enforce_false(is_equal.into())?;
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
                                    circuit.is_equal(solved_vars[m][n], solved_vars[k][l])?;
                                circuit.enforce_false(is_equal.into())?;
                            }
                        }
                    }
                }
            }
        }

        Ok(circuit)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ed_on_bls12_381::EdwardsParameters;
    use ark_std::rand::SeedableRng;
    use jf_plonk::{
        proof_system::{PlonkKzgSnark, UniversalSNARK},
        transcript::StandardTranscript,
    };
    use jf_relation::{Arithmetization, Circuit};
    use rand_chacha::ChaCha20Rng;

    use super::SudokuCircuit;

    #[test]
    fn test_circuit() {
        let circuit: SudokuCircuit<Fr, EdwardsParameters> = SudokuCircuit {
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

        let mut circuit = circuit.synthesize().unwrap();
        // Sanity check: the circuit must be satisfied.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // And we are done!
        circuit.finalize_for_arithmetization().unwrap();

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        // Knowing the circuit size, we are able to simulate the universal
        // setup and obtain the structured reference string (SRS).
        //
        // The required SRS size can be obtained from the circuit.
        let srs_size = circuit.srs_size().unwrap();

        println!("srs_size: {}", srs_size);

        let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng).unwrap();

        // Then, we generate the proving key and verification key from the SRS and
        // circuit.
        let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit).unwrap();

        // Next, we generate the proof.
        // The proof generation will need an internal transcript for Fiat-Shamir
        // transformation. For this example we use a `StandardTranscript`.
        let proof = PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(
            &mut rng, &circuit, &pk, None,
        )
        .unwrap();

        // Last step, verify the proof against the public inputs.
        let public_inputs = circuit.public_input().unwrap();
        // extra messages to bound to proof by appending in its transcripts, not used
        // here.
        let extra_transcript_init_msg = None;
        assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(
            &vk,
            &public_inputs,
            &proof,
            extra_transcript_init_msg,
        )
        .is_ok());
    }
}
