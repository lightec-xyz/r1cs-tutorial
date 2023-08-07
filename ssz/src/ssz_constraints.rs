use core::{borrow::Borrow, iter, marker::PhantomData};
use ark_crypto_primitives::crh::sha256::digest::typenum::{PowerOfTwo, Add1};
use ark_crypto_primitives::crh::{CRHScheme ,CRHSchemeGadget};
use ark_crypto_primitives::crh::sha256::{
    Sha256,
    constraints::{UnitVar,DigestVar, Sha256Gadget}
};
use ark_ff::{PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::constraints::Sha256BytesGadget;
use crate::sha256::Sha256Bytes;
// use crate::constraints::*;

const SHA256_BYTES_INPUT_LEN: usize = 64;
const SHA256_BYTES_DIGEST_LEN: usize = 32;
const G1_POINT_SIZE:usize = 48;

pub struct SSZLayerGadget <ConstraintF:PrimeField> {
    input: Vec<UInt8<ConstraintF>>,
}


impl<ConstraintF: PrimeField> SSZLayerGadget<ConstraintF> {
    pub fn digest(input: &[UInt8<ConstraintF>]) -> Result<DigestVar<ConstraintF>, SynthesisError> { 
        assert!(input.len() >= 64 && input.len() % 64 == 0); 
        let num_pairs: usize = input.len() / 64;
        let mut output_var: Vec<UInt8<ConstraintF>> = Vec::with_capacity(num_pairs * SHA256_BYTES_DIGEST_LEN); 


        for i in 0..num_pairs{
            let digest: DigestVar<ConstraintF> = Sha256BytesGadget::digest(&input[i*64..(i+1)*64].to_vec())?;
            let digest_value = digest.0;
            output_var.extend_from_slice(&digest_value); 
        }
        Ok(DigestVar(output_var))
    }
}


pub struct SSZArrayGadget <ConstraintF:PrimeField> {
    input: Vec<UInt8<ConstraintF>>,
    depth: UInt8<ConstraintF>
}

impl<ConstraintF: PrimeField> SSZArrayGadget<ConstraintF> {
    pub fn digest(input: &[UInt8<ConstraintF>], depth: UInt8<ConstraintF>) -> Result<DigestVar<ConstraintF>, SynthesisError> { //self不是
        assert_eq!(input.len(),32 * (1 << depth.value()?));  
      
        let mut layer_input = input.to_vec();
    
        for i in 0..depth.value()?{
            layer_input = SSZLayerGadget::digest(&layer_input)?.0;
        }
        
        Ok(DigestVar(layer_input))
    }
}


pub struct SSZPhase0SyncCommitteeGadget <ConstraintF:PrimeField> {
    pubkeys: Vec<Vec<UInt8<ConstraintF>>>,
    aggregated_pubkey:Vec<UInt8<ConstraintF>>
}

impl<ConstraintF: PrimeField> SSZPhase0SyncCommitteeGadget<ConstraintF> {
    pub fn digest(
        pubkeys: Vec<Vec<UInt8<ConstraintF>>>, 
        depth: UInt8<ConstraintF>,
        aggregated_pubkey:Vec<UInt8<ConstraintF>>)
         -> Result<DigestVar<ConstraintF>, SynthesisError>{

        let sync_committee_size = pubkeys.len();
        assert_eq!(sync_committee_size, (1<<depth.value()?));
        
        let mut ssz_pubkeys_input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(sync_committee_size * SHA256_BYTES_INPUT_LEN);
        
        let uint8_var_zero: UInt8<ConstraintF> = UInt8::constant(0); 
        for i in 0..sync_committee_size {
            // ssz_pubkeys_input.extend_from_slice(&pubkeys[i]);
            // ssz_pubkeys_input.extend_from_slice(&[uint8_var_zero; 64 - G1_POINT_SIZE]);
    
            for j in 0..SHA256_BYTES_INPUT_LEN {
                if j < G1_POINT_SIZE{
                    ssz_pubkeys_input.push(pubkeys[i][j].clone());
                }else{
                    ssz_pubkeys_input.push(uint8_var_zero.clone());
                }
            }
        }

        let depth_plus_one = depth.value()?+1;
        let depth_plus_one_var = UInt8::constant(depth_plus_one);

        let ssz_pubkeys_output = SSZArrayGadget::digest(&ssz_pubkeys_input, depth_plus_one_var)?;

        Ok(ssz_pubkeys_output)

    }
}


pub struct SSZPhase0BeaconBlockHeaderGadget <ConstraintF:PrimeField> {
    slot: Vec<UInt8<ConstraintF>>,
    proposer_index: Vec<UInt8<ConstraintF>>,
    parent_root:Vec<UInt8<ConstraintF>>,
    state_root: Vec<UInt8<ConstraintF>>,
    body_root: Vec<UInt8<ConstraintF>>,
}

impl<ConstraintF: PrimeField> SSZPhase0BeaconBlockHeaderGadget<ConstraintF> {
    pub fn digest(
        slot: Vec<UInt8<ConstraintF>>, 
        proposer_index:Vec<UInt8<ConstraintF>>,
        parent_root:Vec<UInt8<ConstraintF>>,
        state_root: Vec<UInt8<ConstraintF>>,
        body_root: Vec<UInt8<ConstraintF>>) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        
        assert_eq!(slot.len(),SHA256_BYTES_DIGEST_LEN);
        assert_eq!(proposer_index.len(),SHA256_BYTES_DIGEST_LEN);
        assert_eq!(parent_root.len(),SHA256_BYTES_DIGEST_LEN);
        assert_eq!(state_root.len(),SHA256_BYTES_DIGEST_LEN);
        assert_eq!(body_root.len(),SHA256_BYTES_DIGEST_LEN);

        let mut input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(256);
        
        for i in 0..256 {
            if i < 32{
                input.push(slot[i].clone());
            }else if i < 64{
                input.push(proposer_index[i-32].clone());
            }else if i < 96{
                input.push(parent_root[i-64].clone());
            }else if i < 128{
                input.push(state_root[i-96].clone());
            }else if i < 160{
                input.push(body_root[i-128].clone());
            }else{
                input.push(UInt8::constant(0));
            }
        }

        SSZArrayGadget::digest(&input, UInt8::constant(3))
    }

}


pub struct SSZPhase0SigningRootGadget <ConstraintF:PrimeField> {
    header_root:Vec<UInt8<ConstraintF>>,
    domain: Vec<UInt8<ConstraintF>>
}


impl<ConstraintF: PrimeField> SSZPhase0SigningRootGadget<ConstraintF> {
    pub fn digest(header_root: Vec<UInt8<ConstraintF>>, domain: Vec<UInt8<ConstraintF>>) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        let mut input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(64);

        for i in 0..64 {
            if i < 32{
                input.push(header_root[i].clone());
            }else{
                input.push(domain[i-32].clone());
            }
        }

        let output = SSZLayerGadget::digest(&input)?;
        Ok(output)
    }
}

pub struct SSZRestoreMerkleRootGadget <ConstraintF:PrimeField> {
    depth: UInt8<ConstraintF>,
    index: UInt8<ConstraintF>,
    leaf: Vec<UInt8<ConstraintF>>,
    branch: Vec<Vec<UInt8<ConstraintF>>>,
}

impl<ConstraintF: PrimeField> SSZRestoreMerkleRootGadget<ConstraintF> {
    //TODO(keep)
    pub fn ssz_restore_merkle_root(depth:UInt8<ConstraintF>, index:UInt8<ConstraintF>, leaf:Vec<UInt8<ConstraintF>>, branch:Vec<Vec<UInt8<ConstraintF>>>) -> Vec<UInt8<ConstraintF>>{
        let mut input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(64);
        let mut output: Vec<UInt8<ConstraintF>> = Vec::with_capacity(32);

        let mut first_offset;
        let mut second_offset;

        let index_value =  index.value().unwrap() as usize;
        let depth_value = depth.value().unwrap() as usize;

        for i in 0..depth_value {
            if (index_value / (1 << i)) % 2 == 1 {
                first_offset = 0;
                second_offset = 32;
            } else {
                first_offset = 32;
                second_offset = 0;
            }

            input[first_offset..].copy_from_slice(&branch[i]);
        
            if i == 0 {
                input[second_offset..].copy_from_slice(&leaf);
            }else{
                input[second_offset..].copy_from_slice(&output);
            }
    
            let input_vec = Vec::from(input);
    
            let output_vec = Sha256BytesGadget::digest(&input_vec);

            output = output_vec.unwrap().0;

        }

        output

    }
}


