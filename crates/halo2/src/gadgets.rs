use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

pub mod is_zero;
pub mod not_equal;
pub mod range_check;

/// Check that an expression is in the small range [0..range),
/// i.e. start ≤ word < end.
pub fn range_check<F: FieldExt>(word: Expression<F>, start: usize, end: usize) -> Expression<F> {
    (start..end).fold(
        word.clone() - Expression::Constant(F::from(start as u64)),
        |acc, i| acc * (Expression::Constant(F::from(i as u64)) - word.clone()),
    )
}
