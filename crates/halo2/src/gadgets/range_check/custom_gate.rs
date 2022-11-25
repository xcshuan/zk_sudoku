use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

/// This helper checks that the value witnessed in a given cell is within a given range.
///
///        value     |    q_range_check
///       ------------------------------
///          v       |         1
///

#[derive(Debug, Clone)]
/// A range-constrained value in the circuit produced by the RangeCheckConfig.
pub struct RangeConstrained<F: FieldExt, const START: usize, const END: usize>(
    AssignedCell<Assigned<F>, F>,
);

#[derive(Debug, Clone)]
pub struct RangeCheckConfig<F: FieldExt, const START: usize, const END: usize> {
    pub value: Column<Advice>,
    pub q_range_check: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const START: usize, const END: usize> RangeCheckConfig<F, START, END> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_range_check: Selector,
        value: Column<Advice>,
    ) -> Self {
        meta.create_gate("range check", |meta| {
            //        value     |    q_range_check
            //       ------------------------------
            //          v       |         1

            let q = meta.query_selector(q_range_check);
            let value = meta.query_advice(value, Rotation::cur());

            // Given a start, a end, and a value v, returns the expression
            // (start - v) * (start + 1 - v) * ... * (end - v)
            let range_check = |start: usize, end: usize, value: Expression<F>| {
                assert!(start > 0 && end > start);
                (start + 1..=end).fold(
                    value.clone() - Expression::Constant(F::from(start as u64)),
                    |expr, i| expr * (Expression::Constant(F::from(i as u64)) - value.clone()),
                )
            };

            Constraints::with_selector(q, [("range check", range_check(START, END, value))])
        });

        Self {
            q_range_check,
            value,
            _marker: PhantomData,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
    ) -> Result<RangeConstrained<F, START, END>, Error> {
        layouter.assign_region(
            || "Assign value",
            |mut region| {
                let offset = 0;

                // Enable q_range_check
                self.q_range_check.enable(&mut region, offset)?;

                // Assign value
                region
                    .assign_advice(|| "value", self.value, offset, || value)
                    .map(RangeConstrained)
            },
        )
    }

    pub fn assign_many(
        &self,
        mut layouter: impl Layouter<F>,
        values: &[Value<Assigned<F>>],
    ) -> Result<Vec<RangeConstrained<F, START, END>>, Error> {
        layouter.assign_region(
            || "Assign value",
            |mut region| {
                let mut offset = 0;
                let mut res = vec![];
                for i in 0..values.len() {
                    // Enable q_range_check
                    self.q_range_check.enable(&mut region, offset)?;

                    // Assign value
                    res.push(
                        region
                            .assign_advice(|| "value", self.value, offset, || values[i])
                            .map(RangeConstrained)?,
                    );

                    offset += 1;
                }

                Ok(res)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F: FieldExt, const START: usize, const END: usize> {
        value: Value<Assigned<F>>,
    }

    impl<F: FieldExt, const START: usize, const END: usize> Circuit<F> for MyCircuit<F, START, END> {
        type Config = RangeCheckConfig<F, START, END>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            let q_range_check = meta.selector();
            RangeCheckConfig::configure(meta, q_range_check, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.assign(layouter, self.value)?;
            Ok(())
        }
    }

    #[test]
    fn test_range_check_custom_gate() {
        let k = 4;
        const START: usize = 1;
        const END: usize = 9;

        // Successful cases
        for i in START..=END {
            let circuit = MyCircuit::<Fp, START, END> {
                value: Value::known(Fp::from(i as u64).into()),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // Out-of-range `value = 10`
        {
            let circuit = MyCircuit::<Fp, START, END> {
                value: Value::known(Fp::from((END + 1) as u64).into()),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "range check").into(), 0, "range check").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "Assign value").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0xa".to_string())]
                }])
            );
        }

        // Out-of-range `value = 0`
        {
            let circuit = MyCircuit::<Fp, START, END> {
                value: Value::known(Fp::from(0 as u64).into()),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "range check").into(), 0, "range check").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "Assign value").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0".to_string())]
                }])
            );
        }
    }

    #[derive(Default)]
    struct RangeCircuit<F: FieldExt, const START: usize, const END: usize> {
        values: [u64; 9],
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt, const START: usize, const END: usize> Circuit<F> for RangeCircuit<F, START, END> {
        type Config = RangeCheckConfig<F, START, END>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            let q_range_check = meta.selector();
            RangeCheckConfig::configure(meta, q_range_check, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.assign_many(
                layouter,
                self.values
                    .into_iter()
                    .map(|x| Value::known(F::from(x)).into())
                    .collect::<Vec<_>>()
                    .as_ref(),
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_range_check_custom_gate_many() {
        let k = 9;
        const START: usize = 1;
        const END: usize = 9;

        // Successful cases

        for _j in START..=END {
            let circuit = RangeCircuit::<Fp, START, END> {
                values: [1, 2, 3, 4, 5, 6, 7, 8, 9],
                _marker: PhantomData,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // Out-of-range `value = 8`, `lookup_value = 256`
        {
            let circuit = RangeCircuit::<Fp, START, END> {
                values: [10, 2, 3, 4, 5, 6, 7, 8, 9],
                _marker: PhantomData,
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "range check").into(), 0, "range check").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "Assign value").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0xa".to_string())]
                }])
            );
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 1, 9> {
            value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}
