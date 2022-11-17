use std::time::Instant;

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

use crate::{
    circuit::SudokuCircuit,
    parameters::{
        unsolved_hash, SOLVED, SOLVED_REPEATED_IN_COLUMN, SOLVED_REPEATED_IN_ROW,
        SOLVED_REPEATED_IN_SQUARE,
    },
    parameters::{SOLVED_UNMATCH, UNSOLVED},
};

pub fn run_groth16<F, E>()
where
    E: PairingEngine + PairingEngine<Fr = F>,
    F: PrimeField,
    SudokuCircuit<F>: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    // should success
    let circuit_to_verify_success: SudokuCircuit<<E as PairingEngine>::Fr> = SudokuCircuit {
        unsolved_hash: unsolved_hash(UNSOLVED),
        unsolved: UNSOLVED,
        solved: SOLVED,
    };

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_success
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(is_satisfied);
    {
        // should failed by out of bound
        let mut circuit_to_failed_oob: SudokuCircuit<<E as PairingEngine>::Fr> = SudokuCircuit {
            unsolved_hash: unsolved_hash(UNSOLVED),
            unsolved: UNSOLVED,
            solved: SOLVED,
        };
        circuit_to_failed_oob.solved[0][8] = 10;
        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_oob
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }
    {
        // should failed by out of bound
        let circuit_to_failed_unmatch: SudokuCircuit<<E as PairingEngine>::Fr> = SudokuCircuit {
            unsolved_hash: unsolved_hash(UNSOLVED),
            unsolved: UNSOLVED,
            solved: SOLVED_UNMATCH,
        };
        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_unmatch
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }
    {
        // should failed by repeated numbers in a row
        let circuit_to_failed_repeated_in_row: SudokuCircuit<<E as PairingEngine>::Fr> =
            SudokuCircuit {
                unsolved_hash: unsolved_hash(UNSOLVED),
                unsolved: UNSOLVED,
                solved: SOLVED_REPEATED_IN_ROW,
            };

        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_repeated_in_row
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }
    {
        // should failed by repeated numbers in a column
        let circuit_to_failed_repeated_in_column: SudokuCircuit<<E as PairingEngine>::Fr> =
            SudokuCircuit {
                unsolved_hash: unsolved_hash(UNSOLVED),
                unsolved: UNSOLVED,
                solved: SOLVED_REPEATED_IN_COLUMN,
            };

        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_repeated_in_column
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }

    {
        // should failed by repeated numbers in a square
        let circuit_to_failed_repeated_in_suqare: SudokuCircuit<<E as PairingEngine>::Fr> =
            SudokuCircuit {
                unsolved_hash: unsolved_hash(UNSOLVED),
                unsolved: UNSOLVED,
                solved: SOLVED_REPEATED_IN_SQUARE,
            };

        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_repeated_in_suqare
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }

    {
        // should failed by hash unmatch
        let unsolved_hash = unsolved_hash::<F>(UNSOLVED).add(F::from(1u32));
        let circuit_to_failed_hash_unmatch: SudokuCircuit<<E as PairingEngine>::Fr> =
            SudokuCircuit {
                unsolved_hash,
                unsolved: UNSOLVED,
                solved: SOLVED_REPEATED_IN_SQUARE,
            };

        let cs = ConstraintSystem::new_ref();
        circuit_to_failed_hash_unmatch
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
    }

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
    circuit_to_verify_success
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let prove_start = Instant::now();
    let proof = Groth16::prove(&pk, circuit_to_verify_success.clone(), &mut rng).unwrap();
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
        &[circuit_to_verify_success.unsolved_hash],
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
