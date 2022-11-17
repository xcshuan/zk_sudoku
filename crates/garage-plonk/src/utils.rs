use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk::prelude::Variable;


// check (x-1)(x-2)....(x-9) == 0
pub fn range_check<F: PrimeField, P: TEModelParameters<BaseField = F>>(
    composer: &mut plonk::prelude::StandardComposer<F, P>,
    value: Variable,
) {
    let zero_var = composer.zero_var();
    let res_1 = composer.arithmetic_gate(|gate| {
        gate.witness(value, zero_var, None)
            .constant(-F::from(2u32))
            .add(F::one(), F::zero())
    });
    let res_2 = composer.arithmetic_gate(|gate| {
        gate.witness(value, zero_var, None)
            .constant(-F::one())
            .add(F::one(), F::zero())
    });

    let mut res_mul =
        composer.arithmetic_gate(|gate| gate.witness(res_1, res_2, None).mul(F::one()));
    for r in 3..=9u32 {
        let res = composer.arithmetic_gate(|gate| {
            gate.witness(value, zero_var, None)
                .constant(-F::from(r))
                .add(F::one(), F::zero())
        });
        res_mul = composer.arithmetic_gate(|gate| gate.witness(res_mul, res, None).mul(F::one()));
    }

    composer.assert_equal(res_mul, zero_var);
}
