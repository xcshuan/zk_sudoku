use std::ops::{MulAssign, Sub};

use ark_crypto_primitives::{crh::sha256::constraints::Sha256Gadget, CRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use sha2::Sha256;

#[tracing::instrument(target = "r1cs", skip(value))]
fn enforce_range<F: PrimeField>(value: &UInt8<F>) -> Result<(), SynthesisError> {
    let self_bits = value.to_bits_le()?;
    let self_fe = Boolean::le_bits_to_fp_var(&self_bits)?;
    let mut res_mul = (&self_fe).sub(FpVar::one());
    for i in 2..=9u32 {
        let res = &self_fe - FpVar::Constant(i.into());
        res_mul.mul_assign(res)
    }

    res_mul.enforce_equal(&FpVar::zero())
}

#[derive(Clone)]
pub struct SudokuCircuit<F: PrimeField> {
    pub unsolved_hash: F,
    pub unsolved: [[u8; 9]; 9],
    pub solved: [[u8; 9]; 9],
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SudokuCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        let mut unsolved_var = Vec::with_capacity(9);
        let mut solved_var = Vec::with_capacity(9);

        let sha256_parameter =
            <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::ParametersVar::new_constant(
                cs.clone(),
                (),
            )?;

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        for i in 0..9 {
            unsolved_var.push(Vec::with_capacity(9));
            solved_var.push(Vec::with_capacity(9));
            for j in 0..9 {
                unsolved_var[i].push(UInt8::new_witness(
                    ark_relations::ns!(cs, "unsolved"),
                    || Ok(self.unsolved[i][j]),
                )?);

                solved_var[i].push(UInt8::new_witness(
                    ark_relations::ns!(cs, "solved"),
                    || Ok(self.solved[i][j]),
                )?);

                enforce_range(&solved_var[i][j])?;
            }
        }

        let zero_var = UInt8::new_constant(ark_relations::ns!(cs, "zero"), 0u8)?;
        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        for i in 0..9 {
            for j in 0..9 {
                let is_zero = unsolved_var[i][j].is_eq(&zero_var)?;
                unsolved_var[i][j].conditional_enforce_equal(&solved_var[i][j], &is_zero.not())?;
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

        let hash_input = unsolved_var
            .into_iter()
            .map(|row| row.into_iter().map(|u8_var| u8_var))
            .flatten()
            .collect::<Vec<UInt8<F>>>();

        let hash_result =
            Sha256Gadget::<F>::evaluate(&sha256_parameter, &hash_input)?.to_bytes()?;

        // print!("[");
        // hash_result
        //     .iter()
        //     .for_each(|a| print!("{}, ", a.value().unwrap()));
        // print!("]\n");

        let hash_fe = Boolean::le_bits_to_fp_var(&hash_result[0..31].to_bits_le()?)?;
        // println!("hash_fe: {}", hash_fe.value()?);

        let expected = FpVar::new_input(cs.clone(), || Ok(self.unsolved_hash))?;

        hash_fe.enforce_equal(&expected)?;

        Ok(())
    }
}
