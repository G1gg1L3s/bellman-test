//! This binary demonstrates simple circuit, that proves knowledge of a 32-byte
//! string used to compute a XOR-hash over it (XOR all bytes with each other).

use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::Bls12;
use ff::PrimeField;
use log::LevelFilter;
use rand::rngs::OsRng;

const INPUT_SIZE: usize = 32;

fn native_xor_sum(data: &[u8]) -> u8 {
    assert_eq!(data.len(), INPUT_SIZE);
    data.iter().fold(0, |prev, next| prev ^ next)
}

/// xor-sum gadget. Data should have 32 bytes or 256 boolean elements
fn xor_sum<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(data.len(), INPUT_SIZE * 8);

    let mut byte = vec![Boolean::Constant(false); 8];
    for (i, chunk) in data.chunks(8).enumerate() {
        for (a, b) in byte.iter_mut().zip(chunk.iter()) {
            *a = Boolean::xor(cs.namespace(|| format!("xor [{}]", i)), a, b)?;
        }
    }

    Ok(byte)
}

struct MyCircuit {
    /// The input to xor-sum we are proving that we know. Set to `None` when we
    /// are verifying a proof (and do not have the witness data).
    preimage: Option<[u8; INPUT_SIZE]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Compute the values for the bits of the preimage. If we are verifying a proof,
        // we still need to create the same constraints, so we return an equivalent-size
        // Vec of None (indicating that the value of each bit is unknown).
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; INPUT_SIZE * 8]
        };

        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = xor_sum(cs.namespace(|| "xor_sum(preimage)"), &preimage_bits)?;

        // ??
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

fn main() {
    simple_logging::log_to_stderr(LevelFilter::Debug);
    log::info!("Generating params...");
    let params = {
        let c = MyCircuit { preimage: None };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    log::info!("Preparing the verification key...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    log::info!("Calculating hash...");
    let mut preimage = *b"da confusion of da highest orda!";
    let hash = native_xor_sum(&preimage);

    // Let's flip some bytes. It should not change the hash
    preimage.swap(3, 13);

    // Create an instance of our circuit (with the preimage as a witness).
    let c = MyCircuit {
        preimage: Some(preimage),
    };

    log::info!("Generating proof...");
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

    log::info!("Packing hash as input...");
    let hash_bits = multipack::bytes_to_bits_le(&[hash]);
    let inputs = multipack::compute_multipacking(&hash_bits);

    log::info!("Checking proof...");
    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
    log::info!("Success!");
}
