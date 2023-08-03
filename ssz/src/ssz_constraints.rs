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
    pub fn digest(input: &[UInt8<ConstraintF>]) -> Result<DigestVar<ConstraintF>, SynthesisError> { //self不是
        assert!(input.len() >= 64 && input.len() % 64 == 0);
        let num_pairs: usize = input.len() / 64;
        let mut output_var: Vec<UInt8<ConstraintF>> = Vec::with_capacity(num_pairs * SHA256_BYTES_DIGEST_LEN);  //如何约束？


        for i in 0..num_pairs{
            let digest: DigestVar<ConstraintF> = Sha256BytesGadget::digest((&input[i*64..(i+1)*64].to_vec()))?;
            let digest_value = digest.0;
            output_var.extend_from_slice(&digest_value);  //这会产生约束吗？
        }
        Ok(output_var)
    }
}


pub struct SSZArrayGadget <ConstraintF:PrimeField> {
    input: Vec<UInt8<ConstraintF>>,
    depth: UInt8<ConstraintF>
}

impl<ConstraintF: PrimeField> SSZArrayGadget<ConstraintF> {
    pub fn digest(input: &[UInt8<ConstraintF>], depth: UInt8<ConstraintF>) -> Result<DigestVar<ConstraintF>, SynthesisError> { //self不是
        //assert_eq!(input.len(),32 * (1 << depth));  //how to power for UInt8？
      
        let mut layer_input = input.to_vec();
    
        for i in 0..depth.value()?{
            layer_input = SSZLayerGadget::digest(layer_input).unwrap().0;
        }
        
        Ok(layer_input)
    }
}


pub struct SSZPhase0SyncCommitteeGadget <ConstraintF:PrimeField> {
    pubkeys: Vec<Vec<UInt8<ConstraintF>>>,
    aggregated_pubkey:Vec<UInt8<ConstraintF>>
}

/*
fn ssz_phase0_sync_committee(
    pubkeys: &[[u8; G1_POINT_SIZE]],
    aggregate_pubkey: &[u8; G1_POINT_SIZE],
) -> [u8; 32] {

    let sync_committee_size = pubkeys.len();
    let depth = log2_usize(sync_committee_size);
    let mut ssz_pubkeys_input: Vec<u8> = Vec::with_capacity(sync_committee_size * 64);

    for i in 0..sync_committee_size {
        ssz_pubkeys_input.extend_from_slice(&pubkeys[i]);
        ssz_pubkeys_input.extend_from_slice(&[0u8; 64 - G1_POINT_SIZE]);

        // for j in 0..64 {
        //     if j < G1_POINT_SIZE{
        //         ssz_pubkeys_input.push(pubkeys[i][j]);
        //     }else{
        //         ssz_pubkeys_input.push(0);
        //     }
        // }
    }

    let ssz_pubkeys_output = ssz_array(&ssz_pubkeys_input, depth +1);

    let mut ssz_aggregated_pubkey_input: Vec<u8> = Vec::with_capacity(64);

    ssz_aggregated_pubkey_input.extend_from_slice(aggregate_pubkey);
    ssz_aggregated_pubkey_input.extend_from_slice(&[0u8; 64 - G1_POINT_SIZE]);

    // for i in 0..64 { //TODO, to be optimized
    //     if i < G1_POINT_SIZE{
    //         ssz_aggregated_pubkey_input.push(aggregate_pubkey[i]);
    //     }else{
    //         ssz_aggregated_pubkey_input.push(0);
    //     }
    // }

    let ssz_aggregated_pubkey_output = ssz_layer(&ssz_aggregated_pubkey_input); 

    let mut ssz_layer_input = Vec::with_capacity(64);
    ssz_layer_input.extend_from_slice(&ssz_pubkeys_output);
    ssz_layer_input.extend_from_slice(&ssz_aggregated_pubkey_output);

    let ssz_layer_output = ssz_layer(&ssz_layer_input);
    let result: [u8; 32] = ssz_layer_output[..HASH_SIZE].try_into().unwrap();
    result

}

*/
impl<ConstraintF: PrimeField> SSZPhase0SyncCommitteeGadget<ConstraintF> {
    pub fn digest(
        pubkeys: Vec<Vec<UInt8<ConstraintF>>>, 
        depth: UInt8<ConstraintF>,
        aggregated_pubkey:Vec<UInt8<ConstraintF>>)
         -> Result<DigestVar<ConstraintF>, SynthesisError>{
        
        let sync_committee_size = pubkeys.len();
        assert_eq!(sync_committee_size, (1<<depth.value().unwrap()));
        
        let mut ssz_pubkeys_input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(sync_committee_size * 64);
        
        let uint8_var_zero: UInt8<ConstraintF> = UInt8::constant(0); 
        for i in 0..sync_committee_size {
            // ssz_pubkeys_input.extend_from_slice(&pubkeys[i]);
            // ssz_pubkeys_input.extend_from_slice(&[uint8_var_zero; 64 - G1_POINT_SIZE]);
    
            for j in 0..64 {
                if j < G1_POINT_SIZE{
                    ssz_pubkeys_input.push(pubkeys[i][j]);
                }else{
                    ssz_pubkeys_input.push(UInt8::constant(0));
                }
            }
        }

        let depth_plus_one = UInt8:: :depth + 1;

        let ssz_pubkeys_output = SSZArrayGadget::digest(&ssz_pubkeys_input, depth +1);



        OK()

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
        
        assert_eq!(slot.len(),32);
        assert_eq!(proposer_index.len(),32);
        assert_eq!(parent_root.len(),32);
        assert_eq!(state_root.len(),32);
        assert_eq!(body_root.len(),32);

        let mut input: Vec<UInt8<ConstraintF>> = Vec::with_capacity(256);
        input.extend_from_slice(&slot);
        input.extend_from_slice(&proposer_index);
        input.extend_from_slice(&parent_root);
        input.extend_from_slice(&state_root);
        input.extend_from_slice(&body_root);

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
        input.extend_from_slice(&header_root);
        input.extend_from_slice(&domain);

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
    
}
