use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;

pub type ConstraintF = Fr;
pub type ConstraintE = Bls12_381;

#[derive(Clone)]
pub struct SudokuCircuit<Scalar: PrimeField> {
    pub unsolved: [[Scalar; 9]; 9],
    pub solved: [[Scalar; 9]; 9],
}

impl<Scalar: PrimeField> ConstraintSynthesizer<Scalar> for SudokuCircuit<Scalar> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Scalar>,
    ) -> ark_relations::r1cs::Result<()> {
        let mut unsolved_var = Vec::with_capacity(9);
        let mut solved_var = Vec::with_capacity(9);

        let one_var = FpVar::new_constant(cs.clone(), Scalar::one())?;
        let nine_var = FpVar::new_constant(cs.clone(), Scalar::from(9u32))?;

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        for i in 0..9 {
            unsolved_var.push(Vec::with_capacity(9));
            solved_var.push(Vec::with_capacity(9));
            for j in 0..9 {
                unsolved_var[i].push(FpVar::new_input(
                    ark_relations::ns!(cs, "unsolved"),
                    || Ok(self.unsolved[i][j]),
                )?);

                solved_var[i].push(FpVar::new_witness(
                    ark_relations::ns!(cs, "solved"),
                    || Ok(self.solved[i][j]),
                )?);

                solved_var[i][j].enforce_cmp(&one_var, std::cmp::Ordering::Greater, true)?;
                solved_var[i][j].enforce_cmp(&nine_var, std::cmp::Ordering::Less, true)?;
            }
        }

        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                unsolved_var[i][j].conditional_enforce_not_equal(
                    &solved_var[i][j],
                    &unsolved_var[i][j].is_zero()?,
                )?;
            }
        }

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..j {
                    solved_var[i][k].enforce_not_equal(&solved_var[i][j])?;
                }
            }
        }

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        for i in 0..9 {
            for j in 0..9 {
                for k in 0..i {
                    solved_var[k][j].enforce_not_equal(&solved_var[i][j])?;
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
                                solved_var[m][n].enforce_not_equal(&solved_var[k][l])?
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn main() {
    let circuit_defining_cs: SudokuCircuit<ConstraintF> = SudokuCircuit {
        unsolved: Default::default(),
        solved: Default::default(),
    };
    let mut rng = ark_std::test_rng();

    let setup_start = Instant::now();
    let (pk, vk) =
        Groth16::<ConstraintE>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();
    println!("setup time {}ms", setup_start.elapsed().as_micros());

    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let circuit_to_verify_against: SudokuCircuit<ConstraintF> = SudokuCircuit {
        unsolved: [
            [
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                6.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
            [
                0.into(),
                0.into(),
                7.into(),
                2.into(),
                0.into(),
                0.into(),
                8.into(),
                0.into(),
                0.into(),
            ],
            [
                9.into(),
                0.into(),
                6.into(),
                8.into(),
                0.into(),
                0.into(),
                0.into(),
                1.into(),
                0.into(),
            ],
            [
                3.into(),
                0.into(),
                0.into(),
                7.into(),
                0.into(),
                0.into(),
                0.into(),
                2.into(),
                9.into(),
            ],
            [
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
            [
                4.into(),
                0.into(),
                0.into(),
                5.into(),
                0.into(),
                0.into(),
                0.into(),
                7.into(),
                0.into(),
            ],
            [
                6.into(),
                5.into(),
                0.into(),
                1.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
            [
                8.into(),
                0.into(),
                1.into(),
                0.into(),
                5.into(),
                0.into(),
                3.into(),
                0.into(),
                0.into(),
            ],
            [
                7.into(),
                9.into(),
                2.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                4.into(),
            ],
        ],
        solved: [
            [
                1.into(),
                8.into(),
                4.into(),
                3.into(),
                7.into(),
                6.into(),
                2.into(),
                9.into(),
                5.into(),
            ],
            [
                5.into(),
                3.into(),
                7.into(),
                2.into(),
                9.into(),
                1.into(),
                8.into(),
                4.into(),
                6.into(),
            ],
            [
                9.into(),
                2.into(),
                6.into(),
                8.into(),
                4.into(),
                5.into(),
                7.into(),
                1.into(),
                3.into(),
            ],
            [
                3.into(),
                6.into(),
                5.into(),
                7.into(),
                1.into(),
                8.into(),
                4.into(),
                2.into(),
                9.into(),
            ],
            [
                2.into(),
                7.into(),
                8.into(),
                4.into(),
                6.into(),
                9.into(),
                5.into(),
                3.into(),
                1.into(),
            ],
            [
                4.into(),
                1.into(),
                9.into(),
                5.into(),
                3.into(),
                2.into(),
                6.into(),
                7.into(),
                8.into(),
            ],
            [
                6.into(),
                5.into(),
                3.into(),
                1.into(),
                2.into(),
                4.into(),
                9.into(),
                8.into(),
                7.into(),
            ],
            [
                8.into(),
                4.into(),
                1.into(),
                9.into(),
                5.into(),
                7.into(),
                3.into(),
                6.into(),
                2.into(),
            ],
            [
                7.into(),
                9.into(),
                2.into(),
                6.into(),
                8.into(),
                3.into(),
                1.into(),
                5.into(),
                4.into(),
            ],
        ],
    };

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_against
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let mut public_inputs: Vec<ConstraintF> = circuit_to_verify_against
        .unsolved
        .clone()
        .into_iter()
        .flatten()
        .collect();

    let prove_start = Instant::now();
    let proof = Groth16::prove(&pk, circuit_to_verify_against.clone(), &mut rng).unwrap();
    println!("prove time: {}ms", prove_start.elapsed().as_micros());
    println!("proof len: {}", proof.serialized_size());

    let verify_start = Instant::now();
    let valid_proof = Groth16::verify(&vk, &public_inputs, &proof).unwrap();
    println!("verify time: {}ms", verify_start.elapsed().as_micros());
    assert!(valid_proof);

    public_inputs[5] = 5u32.into();
    let valid_proof = Groth16::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(!valid_proof);
}
