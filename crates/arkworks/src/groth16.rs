use std::time::Instant;

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;

use crate::circuit::SudokuCircuit;

pub fn run_groth16<F, E>()
where
    E: PairingEngine,
    F: PrimeField,
    SudokuCircuit<F>: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    let circuit_defining_cs: SudokuCircuit<F> = SudokuCircuit {
        unsolved: Default::default(),
        solved: Default::default(),
    };
    let mut rng = ark_std::test_rng();

    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();
    let setup_time = setup_start.elapsed();
    println!(
        "setup time {}ms, {}s",
        setup_time.as_micros(),
        setup_time.as_secs()
    );

    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let circuit_to_verify_against: SudokuCircuit<<E as PairingEngine>::Fr> = SudokuCircuit {
        unsolved: [
            [
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                6u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
            ],
            [
                0u32.into(),
                0u32.into(),
                7u32.into(),
                2u32.into(),
                0u32.into(),
                0u32.into(),
                8u32.into(),
                0u32.into(),
                0u32.into(),
            ],
            [
                9u32.into(),
                0u32.into(),
                6u32.into(),
                8u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                1u32.into(),
                0u32.into(),
            ],
            [
                3u32.into(),
                0u32.into(),
                0u32.into(),
                7u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                2u32.into(),
                9u32.into(),
            ],
            [
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
            ],
            [
                4u32.into(),
                0u32.into(),
                0u32.into(),
                5u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                7u32.into(),
                0u32.into(),
            ],
            [
                6u32.into(),
                5u32.into(),
                0u32.into(),
                1u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
            ],
            [
                8u32.into(),
                0u32.into(),
                1u32.into(),
                0u32.into(),
                5u32.into(),
                0u32.into(),
                3u32.into(),
                0u32.into(),
                0u32.into(),
            ],
            [
                7u32.into(),
                9u32.into(),
                2u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                0u32.into(),
                4u32.into(),
            ],
        ],
        solved: [
            [
                1u32.into(),
                8u32.into(),
                4u32.into(),
                3u32.into(),
                7u32.into(),
                6u32.into(),
                2u32.into(),
                9u32.into(),
                5u32.into(),
            ],
            [
                5u32.into(),
                3u32.into(),
                7u32.into(),
                2u32.into(),
                9u32.into(),
                1u32.into(),
                8u32.into(),
                4u32.into(),
                6u32.into(),
            ],
            [
                9u32.into(),
                2u32.into(),
                6u32.into(),
                8u32.into(),
                4u32.into(),
                5u32.into(),
                7u32.into(),
                1u32.into(),
                3u32.into(),
            ],
            [
                3u32.into(),
                6u32.into(),
                5u32.into(),
                7u32.into(),
                1u32.into(),
                8u32.into(),
                4u32.into(),
                2u32.into(),
                9u32.into(),
            ],
            [
                2u32.into(),
                7u32.into(),
                8u32.into(),
                4u32.into(),
                6u32.into(),
                9u32.into(),
                5u32.into(),
                3u32.into(),
                1u32.into(),
            ],
            [
                4u32.into(),
                1u32.into(),
                9u32.into(),
                5u32.into(),
                3u32.into(),
                2u32.into(),
                6u32.into(),
                7u32.into(),
                8u32.into(),
            ],
            [
                6u32.into(),
                5u32.into(),
                3u32.into(),
                1u32.into(),
                2u32.into(),
                4u32.into(),
                9u32.into(),
                8u32.into(),
                7u32.into(),
            ],
            [
                8u32.into(),
                4u32.into(),
                1u32.into(),
                9u32.into(),
                5u32.into(),
                7u32.into(),
                3u32.into(),
                6u32.into(),
                2u32.into(),
            ],
            [
                7u32.into(),
                9u32.into(),
                2u32.into(),
                6u32.into(),
                8u32.into(),
                3u32.into(),
                1u32.into(),
                5u32.into(),
                4u32.into(),
            ],
        ],
    };

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_against
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let mut public_inputs: Vec<<E as PairingEngine>::Fr> = circuit_to_verify_against
        .unsolved
        .clone()
        .into_iter()
        .flatten()
        .collect();

    let prove_start = Instant::now();
    let proof = Groth16::prove(&pk, circuit_to_verify_against.clone(), &mut rng).unwrap();
    let prove_time = prove_start.elapsed();
    println!(
        "prove time {}ms, {}s",
        prove_time.as_micros(),
        prove_time.as_secs()
    );
    println!("proof len: {}", proof.serialized_size());

    let verify_start = Instant::now();
    let valid_proof = Groth16::verify(&vk, &public_inputs, &proof).unwrap();
    let verify_time = verify_start.elapsed();
    println!(
        "verify time {}ms, {}s",
        verify_time.as_micros(),
        verify_time.as_secs()
    );
    assert!(valid_proof);

    public_inputs[5] = 5u32.into();
    let valid_proof = Groth16::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(!valid_proof);
}
