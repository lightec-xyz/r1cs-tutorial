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
        let ssz_pubkeys_output = SSZArrayGadget::digest(&ssz_pubkeys_input, depth_plus_one_var)?.0;


        let mut ssz_aggregated_pubkey_input = Vec::with_capacity(64);
        for j in 0..SHA256_BYTES_INPUT_LEN {
            if j < G1_POINT_SIZE{
                ssz_aggregated_pubkey_input.push(aggregated_pubkey[j].clone());
            }else{
                ssz_aggregated_pubkey_input.push(uint8_var_zero.clone());
            }
        }
        let ssz_aggregated_pubkey_output = SSZLayerGadget::digest(&ssz_aggregated_pubkey_input)?.0; 

        let mut ssz_layer_input = Vec::with_capacity(64);
        for j in 0..SHA256_BYTES_INPUT_LEN {
            if j < 32{
                ssz_layer_input.push(ssz_pubkeys_output[j].clone());
            }else{
                ssz_layer_input.push(ssz_aggregated_pubkey_output[j-32].clone());
            }
        }
        let ssz_layer_output = SSZLayerGadget::digest(&ssz_layer_input);
        ssz_layer_output

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
            
          
            for j in 0..32 {
                input[first_offset + j] = branch[i][j].clone();
            }

            if i == 0{
                for j in 0..32 {
                    input[second_offset + j] = leaf[j].clone();
                }
            }else{
                for j in 0..32 {
                    input[second_offset + j] = output[j].clone();
                }
            }
    
            let input_vec = Vec::from(input.clone());
    
            let output_vec = Sha256BytesGadget::digest(&input_vec);

            output = output_vec.unwrap().0;

        }

        output

    }
}



#[test]
fn test_ssz_layer_gadget(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let input_vec = vec![0u8;64];
    let input_var = to_byte_vars(cs, &input_vec);

    let digest_vec = SSZLayerGadget::digest(&input_var).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    println!("digest_hex {:?}", digest_hex);
}

#[test]
fn test_ssz_array_gadget(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }
    
    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let input_vec = vec![0u8;128];
    let input_var = to_byte_vars(cs, &input_vec);


    let digest_vec = SSZArrayGadget::digest(&input_var,UInt8::constant(2)).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    println!("digest_hex {:?}", digest_hex);
}

#[test]
fn test_ssz_phase0_sync_committee_gadget_8pubkeys(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }
    
    let expect_output = String::from("995690439df3e4cc9bef6be21d8a70c274c4f64fd24f31edbee686f3379aeca8");
    let pubkeys:[[u8; G1_POINT_SIZE]; 8] = [
        [129,68,83,102,92,75,70,218,213,104,214,157,10,61,33,28,112,130,156,231,197,193,117,73,113,62,208,153,108,135,67,230,181,91,55,151,234,25,192,238,186,192,123,14,22,63,174,154],
        [167,27,194,86,23,5,228,146,221,32,103,48,232,215,231,49,230,33,210,215,3,157,237,2,125,153,16,189,65,178,63,100,44,96,153,134,163,63,70,251,49,135,250,246,160,171,193,128],
        [152,17,201,25,182,158,158,203,229,193,41,227,188,108,198,129,29,232,121,20,155,248,86,152,76,194,165,22,42,237,68,86,0,171,172,203,16,161,180,134,148,241,80,222,71,59,137,49],
        [132,200,32,12,130,42,188,134,211,216,211,186,183,145,139,85,150,53,83,191,155,233,210,20,74,54,130,125,182,100,73,226,48,42,73,199,40,55,179,231,147,102,99,33,255,160,164,80],
        [137,203,95,106,242,56,6,134,72,92,74,133,170,70,13,175,255,44,38,129,255,196,221,42,87,173,72,142,83,233,4,115,73,8,250,119,89,209,142,219,126,88,213,74,230,86,87,116],
        [182,7,253,116,136,240,19,182,208,44,209,59,235,62,210,164,29,152,63,2,247,238,172,75,127,66,34,71,66,82,239,69,56,181,176,156,63,231,186,104,153,65,40,57,251,121,88,131],
        [135,253,117,250,247,34,94,157,253,101,187,70,167,149,146,157,26,106,131,17,60,200,156,57,14,242,147,249,183,63,51,97,87,226,244,171,214,134,122,122,58,173,108,176,71,46,31,23],
        [167,63,145,56,34,100,38,136,251,40,148,75,157,247,117,89,58,200,167,123,172,36,96,128,102,88,143,252,17,169,27,12,133,211,240,120,190,19,255,88,111,124,220,32,162,52,115,247]
    ];


    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let mut pubkeys_var = Vec::new();

    for i in 0..pubkeys.len() {
        let pubkey_var: Vec<UInt8<ark_ff::Fp<ark_ff::MontBackend<ark_ed_on_bls12_381::FrConfig, 4>, 4>>> = to_byte_vars(cs.clone(), &pubkeys[i]);
        pubkeys_var.push(pubkey_var);
    }

    let aggregated_pubkey: [u8; G1_POINT_SIZE] = [167,4,92,89,249,203,45,126,62,130,246,60,214,48,74,32,211,109,254,21,228,44,76,134,120,116,15,50,104,47,131,228,170,37,89,73,97,9,75,201,185,24,170,128,48,95,86,85];
    let aggregated_pubkey_var = to_byte_vars(cs, &aggregated_pubkey);


    let digest_vec = SSZPhase0SyncCommitteeGadget::digest(pubkeys_var, UInt8::constant(3), aggregated_pubkey_var).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    // println!("digest_hex {:?}", digest_hex);
    assert_eq!(digest_hex, expect_output);

}



#[test]
fn test_ssz_phase0_beacon_block_header_gadget(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    let expect_output = String::from("93b565f4963da72294d15161b14526aff8b272b209653c8c962f959153904905");
    let slot: [u8;32] = [96,131,102,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let proposer_index:[u8;32] =[116,138,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let parent_root :[u8;32] =[25,17,153,207,115,21,44,235,161,38,251,170,21,199,242,238,61,180,243,254,127,9,38,244,21,243,13,234,47,115,231,123];
    let state_root:[u8;32] = [161,5,99,72,250,0,196,201,7,29,126,227,121,99,227,19,124,84,238,91,16,145,114,71,12,107,224,167,211,224,196,152];
    let body_root:[u8;32] =[164,163,102,126,71,35,230,142,180,146,73,80,179,126,63,52,128,108,47,100,63,180,206,161,170,170,214,71,32,165,22,147];

    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let slot_var = to_byte_vars(cs.clone(), &slot);
    let proposer_index_var = to_byte_vars(cs.clone(), &proposer_index);
    let parent_root_var = to_byte_vars(cs.clone(), &parent_root);
    let state_root_var = to_byte_vars(cs.clone(), &state_root);
    let body_root_var = to_byte_vars(cs.clone(), &body_root);

    let digest_vec  = SSZPhase0BeaconBlockHeaderGadget::digest(slot_var, proposer_index_var, parent_root_var, state_root_var, body_root_var).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    println!("digest_hex {:?}", digest_hex);
    assert_eq!(digest_hex, expect_output);

}



#[test]
fn test_ssz_phase0_signing_root_gadget(){
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use ark_ed_on_bls12_381::Fr;
    use hex;

    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    let expect_output = String::from("88b94b3b9b0d79acb9738e47cecd13fd1cd42b21c8a122c713a3513625802bc8");
    let header_root:[u8;32]= [147,181,101,244,150,61,167,34,148,209,81,97,177,69,38,175,248,178,114,178,9,101,60,140,150,47,149,145,83,144,73,5];
    let domain:[u8;32] = [7,0,0,0,187,164,218,150,53,76,159,37,71,108,241,188,105,191,88,58,127,158,10,240,73,48,91,98,222,103,102,64];


    let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system
    let header_slot_var = to_byte_vars(cs.clone(), &header_root);
    let domain_var = to_byte_vars(cs.clone(), &domain);
 

    let digest_vec  = SSZPhase0SigningRootGadget::digest(header_slot_var, domain_var).unwrap().0;
    let digest_val = digest_vec.value().unwrap();
    let digest_hex = hex::encode(&digest_val);
    println!("digest_hex {:?}", digest_hex);
    assert_eq!(digest_hex, expect_output);

}