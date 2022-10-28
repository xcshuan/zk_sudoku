use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

#[derive(Clone, Debug)]
pub struct NotEqualConfig<F> {
    pub value_inv: Column<Advice>,
    pub is_zero_expr: Expression<F>,
}

impl<F: FieldExt> NotEqualConfig<F> {
    pub fn expr(&self) -> Expression<F> {
        self.is_zero_expr.clone()
    }
}

pub struct NotEqualChip<F: FieldExt> {
    config: NotEqualConfig<F>,
}
