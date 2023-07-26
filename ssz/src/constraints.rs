
use ark_crypto_primitives::crh::{CRHScheme ,CRHSchemeGadget};
use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub type F = ark_ed_on_bls12_381::Fq;


pub struct Sha256BytesCircuit {
    pub input: Vec<u8>,
    // pub output: Vec<u8>,
}


impl ConstraintSynthesizer<F> for Sha256BytesCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let input_var = UInt8::new_input_vec(ark_relations::ns!(cs, "input"), &self.input).unwrap();
        

        Ok(())
    }
}