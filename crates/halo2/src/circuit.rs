use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, Expression, Instance, Selector},
    poly::Rotation,
};

use crate::gadgets::{
    is_zero::{IsZeroChip, IsZeroConfig},
    not_equal::{IsEqualChip, IsEqualConfig},
    range_check::custom_gate::RangeCheckConfig,
};

#[derive(Debug, Clone)]
pub struct SudoukuConfig<F: FieldExt> {
    pub advices: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    pub q_zero_or_equal: Selector,
    pub q_not_equal: Selector,
    pub q_is_zero: Selector,
    pub q_is_equal: Selector,
    pub range_check: RangeCheckConfig<F, 1, 9>,
    pub is_zero: IsZeroConfig<F>,
    pub is_equal: IsEqualConfig<F>,
}

#[derive(Default, Clone)]
struct SudoukuCircuit<F> {
    pub unsolved: [[u64; 9]; 9],
    pub solved: [[u64; 9]; 9],
    pub _marker: PhantomData<F>,
}

impl<F: FieldExt> Circuit<F> for SudoukuCircuit<F> {
    type Config = SudoukuConfig<F>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advices = [meta.advice_column(), meta.advice_column()];

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices {
            meta.enable_equality(advice);
        }

        // used for range check, if use lookup, there should be complex_selector
        let q_range_check = meta.selector();
        let range_check = RangeCheckConfig::configure(meta, q_range_check, advices[1]);

        // used for is_zero check
        let q_is_zero = meta.selector();
        let value_inv = meta.advice_column();
        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_is_zero),
            |meta| meta.query_advice(advices[0], Rotation::cur()),
            value_inv,
        );

        // used for is_equal check
        let q_is_equal = meta.selector();
        let is_equal_col = meta.advice_column();
        let is_equal =
            IsEqualChip::configure(meta, q_is_equal, advices[0], advices[1], is_equal_col);

        let q_zero_or_equal = meta.selector();
        meta.create_gate("enforce is_zero or equal", |meta| {
            let q_enable = meta.query_selector(q_zero_or_equal);
            let is_zero = is_zero.expr();
            let is_equal = is_equal.expr();
            vec![
                q_enable
                    * (Expression::Constant(F::one()) - is_zero)
                    * (Expression::Constant(F::one()) - is_equal),
            ]
        });

        let q_not_equal = meta.selector();
        meta.create_gate("enforce not_equal", |meta| {
            let q_enable = meta.query_selector(q_not_equal);
            let is_equal = is_equal.expr();

            vec![q_enable * is_equal]
        });

        return SudoukuConfig {
            advices,
            instance: primary,
            range_check,
            q_zero_or_equal,
            q_not_equal,
            q_is_zero,
            q_is_equal,
            is_zero,
            is_equal,
        };
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let is_equal = IsEqualChip::construct(config.is_equal);
        let is_zero = IsZeroChip::construct(config.is_zero);

        // if use lookup, uncomment this line
        // config.range_check.load(&mut layouter)?;

        // Check if the numbers of the solved sudoku are >=1 and <=9
        // Each number in the solved sudoku is checked to see if it is >=1 and <=9
        // Check if unsolved is the initial state of solved
        // If unsolved[i][j] is not zero, it means that solved[i][j] is equal to unsolved[i][j]
        // If unsolved[i][j] is zero, it means that solved [i][j] is different from unsolved[i][j]
        let (unsolved_cells, solved_cells) = layouter.assign_region(
            || "range check and match check",
            |mut region| {
                let mut offset = 0;

                let mut unsolved_cells = vec![];
                let mut solved_cells = vec![];

                for i in 0..9 {
                    unsolved_cells.push(vec![]);
                    solved_cells.push(vec![]);
                    for j in 0..9 {
                        let unsolved_value = F::from(self.unsolved[i][j]);
                        let solved_value = F::from(self.solved[i][j]);

                        config.q_zero_or_equal.enable(&mut region, offset)?;
                        config.q_is_equal.enable(&mut region, offset)?;
                        config.q_is_zero.enable(&mut region, offset)?;

                        unsolved_cells[i].push(region.assign_advice(
                            || "unsolved",
                            config.advices[0],
                            offset,
                            || Value::known(unsolved_value),
                        )?);
                        // if use lookup, uncomment this line
                        // config.range_check.q_lookup.enable(&mut region, offset)?;
                        config
                            .range_check
                            .q_range_check
                            .enable(&mut region, offset)?;

                        solved_cells[i].push(region.assign_advice(
                            || "solved",
                            config.advices[1],
                            offset,
                            || Value::known(solved_value),
                        )?);

                        is_zero.assign(&mut region, offset, Value::known(unsolved_value))?;
                        is_equal.assign(
                            &mut region,
                            offset,
                            Value::known(unsolved_value),
                            Value::known(solved_value),
                        )?;

                        offset += 1;
                    }
                }

                Ok((unsolved_cells, solved_cells))
            },
        )?;

        // expose public inputs
        unsolved_cells
            .into_iter()
            .flatten()
            .enumerate()
            .try_for_each(|(i, unsolved)| {
                layouter.constrain_instance(unsolved.cell(), config.instance, i)?;
                Result::<(), halo2_proofs::plonk::Error>::Ok(())
            })?;

        // Check if each row in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same row
        layouter.assign_region(
            || "diff in same row",
            |mut region| {
                let mut offset = 0;
                for i in 0..9 {
                    for j in 0..9 {
                        for k in 0..j {
                            config.q_not_equal.enable(&mut region, offset)?;
                            config.q_is_equal.enable(&mut region, offset)?;
                            solved_cells[i][k].copy_advice(
                                || "i k",
                                &mut region,
                                config.advices[0],
                                offset,
                            )?;
                            solved_cells[i][j].copy_advice(
                                || "i j",
                                &mut region,
                                config.advices[1],
                                offset,
                            )?;
                            is_equal.assign(
                                &mut region,
                                offset,
                                solved_cells[i][k].value().copied(),
                                solved_cells[i][j].value().copied(),
                            )?;
                            offset += 1;
                        }
                    }
                }
                Ok(())
            },
        )?;

        // Check if each column in solved has all the numbers from 1 to 9, both included
        // For each element in solved, check that this element is not equal
        // to previous elements in the same column
        layouter.assign_region(
            || "diff in same column",
            |mut region| {
                let mut offset = 0;
                for i in 0..9 {
                    for j in 0..9 {
                        for k in 0..i {
                            config.q_not_equal.enable(&mut region, offset)?;
                            config.q_is_equal.enable(&mut region, offset)?;
                            solved_cells[k][j].copy_advice(
                                || "k j",
                                &mut region,
                                config.advices[0],
                                offset,
                            )?;
                            solved_cells[i][j].copy_advice(
                                || "i j",
                                &mut region,
                                config.advices[1],
                                offset,
                            )?;
                            is_equal.assign(
                                &mut region,
                                offset,
                                solved_cells[k][j].value().copied(),
                                solved_cells[i][j].value().copied(),
                            )?;
                            offset += 1;
                        }
                    }
                }
                Ok(())
            },
        )?;

        // Check if each square in solved has all the numbers from 1 to 9, both included
        // For each square and for each element in each square, check that the
        // element is not equal to previous elements in the same square
        layouter.assign_region(
            || "diff in same square",
            |mut region| {
                let mut offset = 0;
                for i in [0, 3, 6] {
                    for j in [0, 3, 6] {
                        for k in i..i + 3 {
                            for l in j..j + 3 {
                                for m in i..=k {
                                    for n in j..l {
                                        config.q_not_equal.enable(&mut region, offset)?;
                                        config.q_is_equal.enable(&mut region, offset)?;
                                        solved_cells[m][n].copy_advice(
                                            || "m n",
                                            &mut region,
                                            config.advices[0],
                                            offset,
                                        )?;
                                        solved_cells[k][l].copy_advice(
                                            || "k l",
                                            &mut region,
                                            config.advices[1],
                                            offset,
                                        )?;
                                        is_equal.assign(
                                            &mut region,
                                            offset,
                                            solved_cells[m][n].value().copied(),
                                            solved_cells[k][l].value().copied(),
                                        )?;
                                        offset += 1;
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::{vesta, Fp},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Any, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand::rngs::ThreadRng;

    use super::SudoukuCircuit;

    #[test]
    fn test_circuit() {
        let k = 10;
        let mut circuit = SudoukuCircuit::<Fp> {
            unsolved: [
                [0, 0, 0, 0, 0, 6, 0, 0, 0],
                [0, 0, 7, 2, 0, 0, 8, 0, 0],
                [9, 0, 6, 8, 0, 0, 0, 1, 0],
                [3, 0, 0, 7, 0, 0, 0, 2, 9],
                [0, 0, 0, 0, 0, 0, 0, 0, 0],
                [4, 0, 0, 5, 0, 0, 0, 7, 0],
                [6, 5, 0, 1, 0, 0, 0, 0, 0],
                [8, 0, 1, 0, 5, 0, 3, 0, 0],
                [7, 9, 2, 0, 0, 0, 0, 0, 4],
            ],
            solved: [
                [1, 8, 4, 3, 7, 6, 2, 9, 5],
                [5, 3, 7, 2, 9, 1, 8, 4, 6],
                [9, 2, 6, 8, 4, 5, 7, 1, 3],
                [3, 6, 5, 7, 1, 8, 4, 2, 9],
                [2, 7, 8, 4, 6, 9, 5, 3, 1],
                [4, 1, 9, 5, 3, 2, 6, 7, 8],
                [6, 5, 3, 1, 2, 4, 9, 8, 7],
                [8, 4, 1, 9, 5, 7, 3, 6, 2],
                [7, 9, 2, 6, 8, 3, 1, 5, 4],
            ],
            _marker: std::marker::PhantomData,
        };

        let public_inputs = circuit
            .unsolved
            .iter()
            .flatten()
            .map(|x| Fp::from(*x))
            .collect::<Vec<_>>();
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        prover.assert_satisfied();

        // test proof generation and verification
        {
            // Initialize the polynomial commitment parameters
            let params: Params<vesta::Affine> = Params::new(k);
            // Initialize the proving key
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

            let mut rng = ThreadRng::default();
            // Create a proof
            let prove_start = Instant::now();
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&public_inputs]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
            let proof = transcript.finalize();
            let prove_time = prove_start.elapsed();
            println!(
                "prove time {}ms, {}s",
                prove_time.as_millis(),
                prove_time.as_secs()
            );
            println!("proof size: {}", proof.len());
            {
                let verify_start = Instant::now();
                let strategy = SingleVerifier::new(&params);
                let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
                let verify_result = verify_proof(
                    &params,
                    pk.get_vk(),
                    strategy,
                    &[&[&public_inputs]],
                    &mut transcript,
                );
                let verify_time = verify_start.elapsed();
                println!(
                    "verify time {}ms, {}s",
                    verify_time.as_millis(),
                    verify_time.as_secs()
                );
                assert!(verify_result.is_ok());
            }
        }

        {
            circuit.solved[0][0] = 10;
            let prover = MockProver::run(
                k,
                &circuit,
                vec![circuit
                    .unsolved
                    .iter()
                    .flatten()
                    .map(|x| Fp::from(*x))
                    .collect::<Vec<_>>()],
            )
            .unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "range check").into(), 0, "range check").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "range check and match check").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 1).into(), 0).into(), "0xa".to_string())]
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

        let circuit = SudoukuCircuit::<Fp> {
            unsolved: [
                [0, 0, 0, 0, 0, 6, 0, 0, 0],
                [0, 0, 7, 2, 0, 0, 8, 0, 0],
                [9, 0, 6, 8, 0, 0, 0, 1, 0],
                [3, 0, 0, 7, 0, 0, 0, 2, 9],
                [0, 0, 0, 0, 0, 0, 0, 0, 0],
                [4, 0, 0, 5, 0, 0, 0, 7, 0],
                [6, 5, 0, 1, 0, 0, 0, 0, 0],
                [8, 0, 1, 0, 5, 0, 3, 0, 0],
                [7, 9, 2, 0, 0, 0, 0, 0, 4],
            ],
            solved: [
                [1, 8, 4, 3, 7, 6, 2, 9, 5],
                [5, 3, 7, 2, 9, 1, 8, 4, 6],
                [9, 2, 6, 8, 4, 5, 7, 1, 3],
                [3, 6, 5, 7, 1, 8, 4, 2, 9],
                [2, 7, 8, 4, 6, 9, 5, 3, 1],
                [4, 1, 9, 5, 3, 2, 6, 7, 8],
                [6, 5, 3, 1, 2, 4, 9, 8, 7],
                [8, 4, 1, 9, 5, 7, 3, 6, 2],
                [7, 9, 2, 6, 8, 3, 1, 5, 4],
            ],
            _marker: std::marker::PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(10, &circuit, &root)
            .unwrap();
    }
}
