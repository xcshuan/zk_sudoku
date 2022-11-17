use std::time::Instant;

use ark_ff::PrimeField;
use ark_marlin::{AHPForR1CS, Marlin};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{PCUniversalParams, PolynomialCommitment};
use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode};
use ark_serialize::CanonicalSerialize;
use digest::Digest;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

use crate::{
    circuit::SudokuCircuit,
    parameters::UNSOLVED,
    parameters::{unsolved_hash, SOLVED},
};

pub fn run_marlin<F, PC, D>()
where
    F: PrimeField,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
    D: Digest,
{
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let circuit_to_verify_against: SudokuCircuit<F> = SudokuCircuit {
        unsolved_hash: unsolved_hash(UNSOLVED),
        unsolved: UNSOLVED,
        solved: SOLVED,
    };

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_against
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let circuit_defining_cs: SudokuCircuit<F> = SudokuCircuit {
        unsolved_hash: Default::default(),
        unsolved: Default::default(),
        solved: Default::default(),
    };

    let index = AHPForR1CS::index(circuit_defining_cs.clone()).unwrap();

    let num_constraints: usize = index.index_info.num_constraints;
    let num_variables: usize = index.index_info.num_variables;
    let num_non_zero: usize = index.index_info.num_non_zero;

    println!(
        "Marlin, num_constraints: {}, num_variables: {}, num_non_zero: {}, max_degree: {}",
        num_constraints,
        num_variables,
        num_non_zero,
        index.max_degree()
    );

    let mut rng = &mut ark_std::test_rng();

    let setup_start = Instant::now();
    let universal_srs =
        Marlin::<F, PC, D>::universal_setup(num_constraints, num_variables, num_non_zero, rng)
            .unwrap();
    let setup_time = setup_start.elapsed();
    println!(
        "setup time {}ms, {}s, max_degree: {}",
        setup_time.as_millis(),
        setup_time.as_secs(),
        universal_srs.max_degree(),
    );

    // generate the setup parameters
    let (index_pk, index_vk) =
        Marlin::<F, PC, D>::index(&universal_srs, circuit_defining_cs).unwrap();

    let prove_start = Instant::now();
    let proof =
        Marlin::<F, PC, D>::prove(&index_pk, circuit_to_verify_against.clone(), &mut rng).unwrap();
    let prove_time = prove_start.elapsed();
    println!(
        "prove time {}ms, {}s",
        prove_time.as_millis(),
        prove_time.as_secs()
    );
    println!("proof len: {}", proof.serialized_size());

    let verify_start = Instant::now();
    let valid_proof = Marlin::<F, PC, D>::verify(
        &index_vk,
        &[circuit_to_verify_against.unsolved_hash],
        &proof,
        &mut rng,
    )
    .unwrap();
    let verify_time = verify_start.elapsed();
    println!(
        "verify time {}ms, {}s",
        verify_time.as_millis(),
        verify_time.as_secs()
    );
    assert!(valid_proof);

    let invalid_proof =
        Marlin::<F, PC, D>::verify(&index_vk, &[F::one()], &proof, &mut rng).unwrap();
    assert!(!invalid_proof);
}
