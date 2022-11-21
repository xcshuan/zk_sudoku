use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn range_check<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) {
    let one_var = builder.one();
    let res_1 = builder.sub(value, one_var);

    let two_var = builder.constant(F::from_canonical_u64(2));
    let res_2 = builder.sub(value, two_var);
    let mut res_mul = builder.mul(res_1, res_2);
    for r in 3..=9u64 {
        let r_var = builder.constant(F::from_canonical_u64(r));
        let res = builder.sub(value, r_var);
        res_mul = builder.mul(res_mul, res);
    }
    builder.assert_zero(res_mul);
}
