use ark_ff::FftField;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit, Variable};

pub fn range_check<F: FftField>(
    circuit: &mut PlonkCircuit<F>,
    value: Variable,
) -> Result<(), CircuitError> {
    let res_1 = circuit.sub(value, circuit.one())?;
    let two_var = circuit.create_constant_variable(2u32.into())?;
    let res_2 = circuit.sub(value, two_var)?;
    let mut res_mul = circuit.mul(res_1, res_2)?;

    for r in 3..=9u32 {
        let r_var = circuit.create_constant_variable(r.into())?;
        let res = circuit.sub(value, r_var)?;
        res_mul = circuit.mul(res_mul, res)?;
    }

    circuit.enforce_equal(res_mul, circuit.zero())
}
