use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

mod table;
use table::*;

/// This helper checks that the value witnessed in a given cell is within a given range.
/// Depending on the range, this helper uses either a range-check expression (for small ranges),
/// or a lookup (for large ranges).
///
///        value     |    q_range_check    |   q_lookup  |  table_value  |
///       ----------------------------------------------------------------
///          v_0     |         1           |      0      |       0       |
///          v_1     |         0           |      1      |       1       |
///

#[derive(Debug, Clone)]
/// A range-constrained value in the circuit produced by the RangeCheckConfig.
pub struct RangeConstrained<F: FieldExt, const START: usize, const END: usize>(
    AssignedCell<Assigned<F>, F>,
);

#[derive(Debug, Clone)]
pub struct RangeCheckConfig<F: FieldExt, const START: usize, const END: usize> {
    pub q_lookup: Selector,
    pub value: Column<Advice>,
    pub table: RangeTableConfig<F, START, END>,
}

impl<F: FieldExt, const START: usize, const END: usize> RangeCheckConfig<F, START, END> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_lookup: Selector,
        value: Column<Advice>,
    ) -> Self {
        let table = RangeTableConfig::configure(meta);

        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(q_lookup);
            let value = meta.query_advice(value, Rotation::cur());

            let not_q_lookup = Expression::Constant(F::one()) - q_lookup.clone();
            let default_value = Expression::Constant(F::from(START as u64)); // 0 is a 1-bit value

            let value_expr = q_lookup * value + not_q_lookup * default_value;

            vec![(value_expr, table.value)]
        });

        Self {
            q_lookup,
            value,
            table,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.table.load(layouter)
    }

    pub fn assign_lookup(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
    ) -> Result<RangeConstrained<F, START, END>, Error> {
        layouter.assign_region(
            || "Assign value for lookup range check",
            |mut region| {
                let offset = 0;

                // Enable q_lookup
                self.q_lookup.enable(&mut region, offset)?;

                // Assign value
                region
                    .assign_advice(|| "value", self.value, offset, || value)
                    .map(RangeConstrained)
            },
        )
    }

    pub fn assign_lookup_many(
        &self,
        mut layouter: impl Layouter<F>,
        values: &[Value<Assigned<F>>],
    ) -> Result<Vec<RangeConstrained<F, START, END>>, Error> {
        layouter.assign_region(
            || "Assign many values for lookup range check",
            |mut region| {
                let mut offset = 0;
                let mut res = vec![];
                for i in 0..values.len() {
                    // Enable q_lookup
                    self.q_lookup.enable(&mut region, offset)?;

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
    use std::marker::PhantomData;

    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::Circuit,
    };

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F: FieldExt, const START: usize, const END: usize> {
        lookup_value: Value<Assigned<F>>,
    }

    impl<F: FieldExt, const START: usize, const END: usize> Circuit<F> for MyCircuit<F, START, END> {
        type Config = RangeCheckConfig<F, START, END>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            let q_lookup = meta.complex_selector();
            RangeCheckConfig::configure(meta, q_lookup, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;
            config.assign_lookup(layouter, self.lookup_value)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_check_lookup() {
        let k = 9;
        const START: usize = 1;
        const END: usize = 9;

        // Successful cases

        for j in START..=END {
            let circuit = MyCircuit::<Fp, START, END> {
                lookup_value: Value::known(Fp::from(j as u64).into()),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // Out-of-range `value = 8`, `lookup_value = 256`
        {
            let circuit = MyCircuit::<Fp, START, END> {
                lookup_value: Value::known(Fp::from((END + 1) as u64).into()),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::Lookup {
                    lookup_index: 0,
                    location: FailureLocation::InRegion {
                        region: (1, "Assign value for lookup range check").into(),
                        offset: 0
                    }
                }])
            );
        }
    }

    #[derive(Default)]
    struct RangeCircuit<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> {
        lookup_values: [u64; 9],
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<F>
        for RangeCircuit<F, RANGE, LOOKUP_RANGE>
    {
        type Config = RangeCheckConfig<F, RANGE, LOOKUP_RANGE>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            let q_lookup = meta.complex_selector();
            RangeCheckConfig::configure(meta, q_lookup, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;
            config.assign_lookup_many(
                layouter,
                self.lookup_values
                    .into_iter()
                    .map(|x| Value::known(F::from(x)).into())
                    .collect::<Vec<_>>()
                    .as_ref(),
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_range_check_lookup_many() {
        let k = 9;
        const START: usize = 1;
        const END: usize = 9;

        // Successful cases

        for _j in START..=END {
            let circuit = RangeCircuit::<Fp, START, END> {
                lookup_values: [1, 2, 3, 4, 5, 6, 7, 8, 9],
                _marker: PhantomData,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // Out-of-range `value = 8`, `lookup_value = 256`
        {
            let circuit = RangeCircuit::<Fp, START, END> {
                lookup_values: [10, 2, 3, 4, 5, 6, 7, 8, 9],
                _marker: PhantomData,
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::Lookup {
                    lookup_index: 0,
                    location: FailureLocation::InRegion {
                        region: (1, "Assign many values for lookup range check").into(),
                        offset: 0
                    }
                }])
            );
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_2() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-2-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 2 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 1, 9> {
            lookup_value: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }
}
