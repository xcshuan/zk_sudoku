use dusk_plonk::prelude::*;

pub fn range_check<C: Composer>(composer: &mut C, value: Witness) {
    let s = Constraint::new()
        .left(1)
        .constant(-(<u64 as Into<BlsScalar>>::into(1)))
        .a(value);
    let res_1 = composer.gate_add(s);

    let s = Constraint::new()
        .left(1)
        .constant(-(<u64 as Into<BlsScalar>>::into(2)))
        .a(value);
    let res_2 = composer.gate_add(s);

    let s_mul = Constraint::new().mult(1).a(res_1).b(res_2);
    let mut res_mul = composer.gate_mul(s_mul);

    for r in 3..=9 {
        let s = Constraint::new()
            .left(1)
            .constant(-(<u64 as Into<BlsScalar>>::into(r)))
            .a(value);
        let res = composer.gate_add(s);
        let s_mul = Constraint::new().mult(1).a(res).b(res_mul);
        res_mul = composer.gate_mul(s_mul);
    }

    composer.assert_equal_constant(res_mul, 0, None)
}

/// A gate which outputs a variable whose value is 1 if
/// the input is 0 and whose value is 0 otherwise
pub fn is_zero_with_output<C: Composer>(composer: &mut C, a: Witness) -> Witness {
    // Get relevant field values
    let a_value = composer.index(a);
    let y_value = a_value.invert().unwrap_or_else(|| BlsScalar::one());

    // This has value 1 if input value is zero, value 0 otherwise
    let b_value = BlsScalar::one() - *a_value * y_value;

    let y = composer.append_witness(y_value);
    let b = composer.append_witness(b_value);

    // Enforce constraints. The constraint system being used here is
    // a * y + b - 1 = 0
    // a * b = 0
    // where y is auxiliary and b is the boolean (a == 0).
    let a_times_b = Constraint::new().a(a).b(b).mult(BlsScalar::one());
    let _a_times_b = composer.gate_add(a_times_b);

    let first_constraint = Constraint::new()
        .a(a)
        .b(y)
        .d(b)
        .constant(-BlsScalar::one())
        .fourth(BlsScalar::one())
        .mult(BlsScalar::one());
    let _first_constraint = composer.gate_add(first_constraint);

    b
}

/// A gate which outputs a variable whose value is 1 if the
/// two input variables have equal values and whose value is 0 otherwise.
pub fn is_eq_with_output<C: Composer>(composer: &mut C, a: Witness, b: Witness) -> Witness {
    let s = Constraint::new()
        .a(a)
        .b(b)
        .left(BlsScalar::one())
        .right(-BlsScalar::one());
    let difference = composer.gate_add(s);
    is_zero_with_output(composer, difference)
}
