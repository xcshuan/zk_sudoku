use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, Instance, Selector},
};

#[derive(Debug, Clone)]
struct SudoukuConfig {
    pub advices: [Column<Advice>; 9],
    pub instance: Column<Instance>,
}

#[derive(Default)]
struct SudoukuCircuit<F> {
    pub unsolved: [[Value<F>; 9]; 9],
    pub solved: [[Value<F>; 9]; 9],
}

impl<F: FieldExt> Circuit<F> for SudoukuCircuit<F> {
    type Config = SudoukuConfig;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }
        
        return SudoukuConfig {
            advices,
            instance: primary,
        };
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        todo!()
    }
}
