use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

use super::is_zero::{IsZeroChip, IsZeroConfig};

#[derive(Clone, Debug)]
pub struct IsEqualConfig<F> {
    pub q_enable: Selector,
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub is_zero_config: IsZeroConfig<F>,
}

impl<F: FieldExt> IsEqualConfig<F> {
    pub fn expr(&self) -> Expression<F> {
        self.is_zero_config.expr()
    }
}

pub struct IsEqualChip<F: FieldExt> {
    config: IsEqualConfig<F>,
}

impl<F: FieldExt> IsEqualChip<F> {
    pub fn construct(config: IsEqualConfig<F>) -> Self {
        IsEqualChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: Selector,
        a: Column<Advice>,
        b: Column<Advice>,
        is_equal: Column<Advice>,
    ) -> IsEqualConfig<F> {
        let is_zero_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| {
                let a = meta.query_advice(a, Rotation::cur());
                let b = meta.query_advice(b, Rotation::cur());
                a - b
            },
            is_equal,
        );

        IsEqualConfig {
            q_enable,
            a,
            b,
            is_zero_config,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Value<F>,
        b: Value<F>,
    ) -> Result<(), Error> {
        let value = a - b;
        let value_inv = value.map(|value| value.invert().unwrap_or(F::zero()));
        region.assign_advice(
            || "value inv",
            self.config.is_zero_config.value_inv,
            offset,
            || value_inv,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::Circuit,
    };

    use super::*;

    #[derive(Default)]
    struct NotEqualCircuit<F: FieldExt> {
        a: F,
        b: F,
    }

    impl<F: FieldExt> Circuit<F> for NotEqualCircuit<F> {
        type Config = IsEqualConfig<F>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable = meta.selector();
            let a_col = meta.advice_column();
            let b_col = meta.advice_column();
            let is_equal = meta.advice_column();
            let config = IsEqualChip::configure(meta, q_enable, a_col, b_col, is_equal);

            meta.create_gate("chech is_not_equal", |meta| {
                let q_enable = meta.query_selector(q_enable);
                let is_equal = config.expr();

                vec![q_enable * is_equal]
            });

            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let is_equal = IsEqualChip::construct(config);

            layouter.assign_region(
                || "a != b",
                |mut region| {
                    is_equal.config.q_enable.enable(&mut region, 0)?;
                    region.assign_advice(|| "a", is_equal.config.a, 0, || Value::known(self.a))?;
                    region.assign_advice(|| "b", is_equal.config.b, 0, || Value::known(self.b))?;

                    is_equal.assign(&mut region, 0, Value::known(self.a), Value::known(self.b))
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_not_equal() {
        let k = 4;

        // Successful cases

        let circuit = NotEqualCircuit::<Fp> {
            a: Fp::from(1 as u64).into(),
            b: Fp::from(2 as u64).into(),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        {
            let circuit = NotEqualCircuit::<Fp> {
                a: Fp::from(1 as u64).into(),
                b: Fp::from(1 as u64).into(),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((1, "chech is_not_equal").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "a != b").into(),
                        offset: 0
                    },
                    cell_values: vec![]
                }])
            );
        }
    }
}
