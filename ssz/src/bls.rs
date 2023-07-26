use ark_bls12_381::{
    g1::Config as G1Config, g2::Config as G2Config, Bls12_381, G1Affine, G2Affine,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::field_hashers::DefaultFieldHasher;
use hex_literal::hex;
use sha2::Sha256;



