use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::ConstraintSynthesizer;

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
