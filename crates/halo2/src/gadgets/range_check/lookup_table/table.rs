use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone)]
pub struct RangeTableConfig<F: FieldExt, const START: usize, const END: usize> {
    pub value: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const START: usize, const END: usize> RangeTableConfig<F, START, END> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let value = meta.lookup_table_column();

        Self {
            value,
            _marker: PhantomData,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table| {
                let mut offset = 0;
                for value in START..=END {
                    table.assign_cell(
                        || "num_bits",
                        self.value,
                        offset,
                        || Value::known(F::from(value as u64)),
                    )?;
                    offset += 1;
                }

                Ok(())
            },
        )
    }
}
