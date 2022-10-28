use std::time::Instant;

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use digest::Digest;

use crate::{circuit::SudokuCircuit, parameters::SOLVED, parameters::UNSOLVED};

pub fn run_groth16<F, E>()
where
    E: PairingEngine + PairingEngine<Fr = F>,
    F: PrimeField,
    SudokuCircuit<F>: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    let hash_result = sha2::Sha256::digest(
        &UNSOLVED
            .into_iter()
            .map(|a| a.into_iter().map(|a| a.0))
            .flatten()
            .collect::<Vec<u8>>(),
    )
    .to_vec();

    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let circuit_to_verify_against: SudokuCircuit<<E as PairingEngine>::Fr> = SudokuCircuit {
        unsolved_hash: F::from_le_bytes_mod_order(&hash_result[..31]),
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
    let mut rng = ark_std::test_rng();

    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();
    let processed_vk = Groth16::process_vk(&vk).unwrap();
    let setup_time = setup_start.elapsed();
    println!(
        "setup time {}ms, {}s",
        setup_time.as_millis(),
        setup_time.as_secs()
    );

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_against
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let prove_start = Instant::now();
    let proof = Groth16::prove(&pk, circuit_to_verify_against.clone(), &mut rng).unwrap();
    let prove_time = prove_start.elapsed();
    println!(
        "prove time {}ms, {}s",
        prove_time.as_millis(),
        prove_time.as_secs()
    );
    println!("proof len: {}", proof.serialized_size());

    let verify_start = Instant::now();
    let valid_proof = Groth16::verify_with_processed_vk(
        &processed_vk,
        &[circuit_to_verify_against.unsolved_hash],
        &proof,
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
        Groth16::verify_with_processed_vk(&processed_vk, &[F::one()], &proof).unwrap();
    assert!(!invalid_proof);
}
