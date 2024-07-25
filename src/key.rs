// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(non_camel_case_types)]

use byteorder::{BigEndian, ByteOrder};
use std::collections::HashMap;
use substrate_bn::{AffineG1, FieldError, Fq, GroupError, G1};

#[derive(Debug, thiserror::Error)]
pub enum VerificationKeyError {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid field '{field}': {error:?}")]
    InvalidField {
        field: &'static str,
        error: FieldError,
    },
    #[error("Invalid group '{field}': {error:?}")]
    InvalidGroup {
        field: &'static str,
        error: GroupError,
    },
    #[error("Invalid circuit type: {value:?}")]
    InvalidCircuitType { value: u32 },
    #[error("Invalid commitment field: {value:?}")]
    InvalidCommitmentField { value: String },
    #[error("Invalid commitment list number: {value:?}")]
    InvalidCommitmentListNumber { value: usize },
    #[error("Invalid commitment key at offset {offset:?}")]
    InvalidCommitmentKey { offset: usize },
    #[error("Missing commitment field: {field:?}")]
    MissingCommitmentField { field: CommitmentField },
    #[error("Recursion is not supported")]
    RecursionNotSupported,
}

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey {
    pub circuit_type: u32,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub q_1: G1,
    pub q_2: G1,
    pub q_3: G1,
    pub q_4: G1,
    pub q_m: G1,
    pub q_c: G1,
    pub q_arithmetic: G1,
    pub q_sort: G1,
    pub q_elliptic: G1,
    pub q_aux: G1,
    pub sigma_1: G1,
    pub sigma_2: G1,
    pub sigma_3: G1,
    pub sigma_4: G1,
    pub table_1: G1,
    pub table_2: G1,
    pub table_3: G1,
    pub table_4: G1,
    pub table_type: G1,
    pub id_1: G1,
    pub id_2: G1,
    pub id_3: G1,
    pub id_4: G1,
    pub contains_recursive_proof: bool,
    pub recursive_proof_public_inputs_size: u32,
    pub is_recursive_circuit: bool,
}

impl VerificationKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.circuit_type.to_be_bytes());
        data.extend_from_slice(&self.circuit_size.to_be_bytes());
        data.extend_from_slice(&self.num_public_inputs.to_be_bytes());

        // Commitments size
        data.extend_from_slice(&23u32.to_be_bytes());

        write_g1(&CommitmentField::Q_1, self.q_1, &mut data);
        write_g1(&CommitmentField::Q_2, self.q_2, &mut data);
        write_g1(&CommitmentField::Q_3, self.q_3, &mut data);
        write_g1(&CommitmentField::Q_4, self.q_4, &mut data);
        write_g1(&CommitmentField::Q_M, self.q_m, &mut data);
        write_g1(&CommitmentField::Q_C, self.q_c, &mut data);
        write_g1(&CommitmentField::Q_ARITHMETIC, self.q_arithmetic, &mut data);
        write_g1(&CommitmentField::Q_SORT, self.q_sort, &mut data);
        write_g1(&CommitmentField::Q_ELLIPTIC, self.q_elliptic, &mut data);
        write_g1(&CommitmentField::Q_AUX, self.q_aux, &mut data);
        write_g1(&CommitmentField::SIGMA_1, self.sigma_1, &mut data);
        write_g1(&CommitmentField::SIGMA_2, self.sigma_2, &mut data);
        write_g1(&CommitmentField::SIGMA_3, self.sigma_3, &mut data);
        write_g1(&CommitmentField::SIGMA_4, self.sigma_4, &mut data);
        write_g1(&CommitmentField::TABLE_1, self.table_1, &mut data);
        write_g1(&CommitmentField::TABLE_2, self.table_2, &mut data);
        write_g1(&CommitmentField::TABLE_3, self.table_3, &mut data);
        write_g1(&CommitmentField::TABLE_4, self.table_4, &mut data);
        write_g1(&CommitmentField::TABLE_TYPE, self.table_type, &mut data);
        write_g1(&CommitmentField::ID_1, self.id_1, &mut data);
        write_g1(&CommitmentField::ID_2, self.id_2, &mut data);
        write_g1(&CommitmentField::ID_3, self.id_3, &mut data);
        write_g1(&CommitmentField::ID_4, self.id_4, &mut data);

        // Contains recursive proof
        data.push(if self.contains_recursive_proof { 1 } else { 0 });
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(if self.is_recursive_circuit { 1 } else { 0 });

        data
    }
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = VerificationKeyError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 1719 {
            return Err(VerificationKeyError::BufferTooShort);
        }
        let circuit_type = BigEndian::read_u32(&data[0..4]);
        if circuit_type != 2 {
            return Err(VerificationKeyError::InvalidCircuitType {
                value: circuit_type,
            });
        }

        let circuit_size = BigEndian::read_u32(&data[4..8]);
        let num_public_inputs = BigEndian::read_u32(&data[8..12]);
        let mut commitments_num = BigEndian::read_u32(&data[12..16]) as usize;

        let mut commitments = HashMap::new();
        let mut i = 16;
        let u32_size = 4;
        while i < data.len() && commitments_num > 0 {
            let key_size = BigEndian::read_u32(&data[i..i + u32_size]) as usize;
            i += u32_size;
            let key = String::from_utf8(data[i..i + key_size].to_vec())
                .map_err(|_| VerificationKeyError::InvalidCommitmentKey { offset: i })?;
            i += key_size;
            let field = CommitmentField::try_from(&key)
                .map_err(|_| VerificationKeyError::InvalidCommitmentField { value: key })?;
            let commitment = read_g1(&field, &data[i..i + 64])?;
            i += 64;

            commitments.insert(field, commitment);
            commitments_num -= 1;
        }

        if commitments_num != 0 {
            return Err(VerificationKeyError::InvalidCommitmentListNumber {
                value: commitments_num,
            });
        }

        let contains_recursive_proof = data[i] == 1;
        if contains_recursive_proof {
            return Err(VerificationKeyError::RecursionNotSupported);
        }
        i += 1;
        let recursive_proof_public_inputs_size = BigEndian::read_u32(&data[i..i + u32_size]);
        i += u32_size;
        if recursive_proof_public_inputs_size != 0 {
            return Err(VerificationKeyError::RecursionNotSupported);
        }
        let is_recursive_circuit = data[i] == 1;
        if is_recursive_circuit {
            return Err(VerificationKeyError::RecursionNotSupported);
        }

        Ok(Self {
            circuit_type,
            circuit_size,
            num_public_inputs,
            q_1: remove_commitment_field(&mut commitments, CommitmentField::Q_1)?,
            q_2: remove_commitment_field(&mut commitments, CommitmentField::Q_2)?,
            q_3: remove_commitment_field(&mut commitments, CommitmentField::Q_3)?,
            q_4: remove_commitment_field(&mut commitments, CommitmentField::Q_4)?,
            q_m: remove_commitment_field(&mut commitments, CommitmentField::Q_M)?,
            q_c: remove_commitment_field(&mut commitments, CommitmentField::Q_C)?,
            q_arithmetic: remove_commitment_field(&mut commitments, CommitmentField::Q_ARITHMETIC)?,
            q_sort: remove_commitment_field(&mut commitments, CommitmentField::Q_SORT)?,
            q_elliptic: remove_commitment_field(&mut commitments, CommitmentField::Q_ELLIPTIC)?,
            q_aux: remove_commitment_field(&mut commitments, CommitmentField::Q_AUX)?,
            sigma_1: remove_commitment_field(&mut commitments, CommitmentField::SIGMA_1)?,
            sigma_2: remove_commitment_field(&mut commitments, CommitmentField::SIGMA_2)?,
            sigma_3: remove_commitment_field(&mut commitments, CommitmentField::SIGMA_3)?,
            sigma_4: remove_commitment_field(&mut commitments, CommitmentField::SIGMA_4)?,
            table_1: remove_commitment_field(&mut commitments, CommitmentField::TABLE_1)?,
            table_2: remove_commitment_field(&mut commitments, CommitmentField::TABLE_2)?,
            table_3: remove_commitment_field(&mut commitments, CommitmentField::TABLE_3)?,
            table_4: remove_commitment_field(&mut commitments, CommitmentField::TABLE_4)?,
            table_type: remove_commitment_field(&mut commitments, CommitmentField::TABLE_TYPE)?,
            id_1: remove_commitment_field(&mut commitments, CommitmentField::ID_1)?,
            id_2: remove_commitment_field(&mut commitments, CommitmentField::ID_2)?,
            id_3: remove_commitment_field(&mut commitments, CommitmentField::ID_3)?,
            id_4: remove_commitment_field(&mut commitments, CommitmentField::ID_4)?,
            contains_recursive_proof,
            recursive_proof_public_inputs_size,
            is_recursive_circuit,
        })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CommitmentField {
    Q_1,
    Q_2,
    Q_3,
    Q_4,
    Q_M,
    Q_C,
    Q_ARITHMETIC,
    Q_SORT,
    Q_ELLIPTIC,
    Q_AUX,
    SIGMA_1,
    SIGMA_2,
    SIGMA_3,
    SIGMA_4,
    TABLE_1,
    TABLE_2,
    TABLE_3,
    TABLE_4,
    TABLE_TYPE,
    ID_1,
    ID_2,
    ID_3,
    ID_4,
}

impl CommitmentField {
    fn str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1",
            CommitmentField::Q_2 => "Q_2",
            CommitmentField::Q_3 => "Q_3",
            CommitmentField::Q_4 => "Q_4",
            CommitmentField::Q_M => "Q_M",
            CommitmentField::Q_C => "Q_C",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC",
            CommitmentField::Q_SORT => "Q_SORT",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC",
            CommitmentField::Q_AUX => "Q_AUX",
            CommitmentField::SIGMA_1 => "SIGMA_1",
            CommitmentField::SIGMA_2 => "SIGMA_2",
            CommitmentField::SIGMA_3 => "SIGMA_3",
            CommitmentField::SIGMA_4 => "SIGMA_4",
            CommitmentField::TABLE_1 => "TABLE_1",
            CommitmentField::TABLE_2 => "TABLE_2",
            CommitmentField::TABLE_3 => "TABLE_3",
            CommitmentField::TABLE_4 => "TABLE_4",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE",
            CommitmentField::ID_1 => "ID_1",
            CommitmentField::ID_2 => "ID_2",
            CommitmentField::ID_3 => "ID_3",
            CommitmentField::ID_4 => "ID_4",
        }
    }

    fn x_str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1.x",
            CommitmentField::Q_2 => "Q_2.x",
            CommitmentField::Q_3 => "Q_3.x",
            CommitmentField::Q_4 => "Q_4.x",
            CommitmentField::Q_M => "Q_M.x",
            CommitmentField::Q_C => "Q_C.x",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC.x",
            CommitmentField::Q_SORT => "Q_SORT.x",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC.x",
            CommitmentField::Q_AUX => "Q_AUX.x",
            CommitmentField::SIGMA_1 => "SIGMA_1.x",
            CommitmentField::SIGMA_2 => "SIGMA_2.x",
            CommitmentField::SIGMA_3 => "SIGMA_3.x",
            CommitmentField::SIGMA_4 => "SIGMA_4.x",
            CommitmentField::TABLE_1 => "TABLE_1.x",
            CommitmentField::TABLE_2 => "TABLE_2.x",
            CommitmentField::TABLE_3 => "TABLE_3.x",
            CommitmentField::TABLE_4 => "TABLE_4.x",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE.x",
            CommitmentField::ID_1 => "ID_1.x",
            CommitmentField::ID_2 => "ID_2.x",
            CommitmentField::ID_3 => "ID_3.x",
            CommitmentField::ID_4 => "ID_4.x",
        }
    }

    fn y_str(&self) -> &'static str {
        match self {
            CommitmentField::Q_1 => "Q_1.y",
            CommitmentField::Q_2 => "Q_2.y",
            CommitmentField::Q_3 => "Q_3.y",
            CommitmentField::Q_4 => "Q_4.y",
            CommitmentField::Q_M => "Q_M.y",
            CommitmentField::Q_C => "Q_C.y",
            CommitmentField::Q_ARITHMETIC => "Q_ARITHMETIC.y",
            CommitmentField::Q_SORT => "Q_SORT.y",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC.y",
            CommitmentField::Q_AUX => "Q_AUX.y",
            CommitmentField::SIGMA_1 => "SIGMA_1.y",
            CommitmentField::SIGMA_2 => "SIGMA_2.y",
            CommitmentField::SIGMA_3 => "SIGMA_3.y",
            CommitmentField::SIGMA_4 => "SIGMA_4.y",
            CommitmentField::TABLE_1 => "TABLE_1.y",
            CommitmentField::TABLE_2 => "TABLE_2.y",
            CommitmentField::TABLE_3 => "TABLE_3.y",
            CommitmentField::TABLE_4 => "TABLE_4.y",
            CommitmentField::TABLE_TYPE => "TABLE_TYPE.y",
            CommitmentField::ID_1 => "ID_1.y",
            CommitmentField::ID_2 => "ID_2.y",
            CommitmentField::ID_3 => "ID_3.y",
            CommitmentField::ID_4 => "ID_4.y",
        }
    }

    fn try_from(value: &str) -> Result<Self, String> {
        match value {
            "Q_1" => Ok(CommitmentField::Q_1),
            "Q_2" => Ok(CommitmentField::Q_2),
            "Q_3" => Ok(CommitmentField::Q_3),
            "Q_4" => Ok(CommitmentField::Q_4),
            "Q_M" => Ok(CommitmentField::Q_M),
            "Q_C" => Ok(CommitmentField::Q_C),
            "Q_ARITHMETIC" => Ok(CommitmentField::Q_ARITHMETIC),
            "Q_SORT" => Ok(CommitmentField::Q_SORT),
            "Q_ELLIPTIC" => Ok(CommitmentField::Q_ELLIPTIC),
            "Q_AUX" => Ok(CommitmentField::Q_AUX),
            "SIGMA_1" => Ok(CommitmentField::SIGMA_1),
            "SIGMA_2" => Ok(CommitmentField::SIGMA_2),
            "SIGMA_3" => Ok(CommitmentField::SIGMA_3),
            "SIGMA_4" => Ok(CommitmentField::SIGMA_4),
            "TABLE_1" => Ok(CommitmentField::TABLE_1),
            "TABLE_2" => Ok(CommitmentField::TABLE_2),
            "TABLE_3" => Ok(CommitmentField::TABLE_3),
            "TABLE_4" => Ok(CommitmentField::TABLE_4),
            "TABLE_TYPE" => Ok(CommitmentField::TABLE_TYPE),
            "ID_1" => Ok(CommitmentField::ID_1),
            "ID_2" => Ok(CommitmentField::ID_2),
            "ID_3" => Ok(CommitmentField::ID_3),
            "ID_4" => Ok(CommitmentField::ID_4),
            _ => Err(format!("Invalid commitment field '{}'", value)),
        }
    }
}

fn remove_commitment_field(
    commitments: &mut HashMap<CommitmentField, G1>,
    field: CommitmentField,
) -> Result<G1, VerificationKeyError> {
    commitments
        .remove(&field)
        .ok_or(VerificationKeyError::MissingCommitmentField { field })
}

fn read_g1(field: &CommitmentField, data: &[u8]) -> Result<G1, VerificationKeyError> {
    let x = read_fq(field.x_str(), &data[0..32])?;
    let y = read_fq(field.y_str(), &data[32..64])?;
    AffineG1::new(x, y)
        .map_err(|e| VerificationKeyError::InvalidGroup {
            field: field.str(),
            error: e,
        })
        .map(Into::into)
}

fn read_fq(addr: &'static str, data: &[u8]) -> Result<Fq, VerificationKeyError> {
    Fq::from_slice(data).map_err(|e| VerificationKeyError::InvalidField {
        field: addr,
        error: e,
    })
}

fn write_g1(field: &CommitmentField, g1: G1, data: &mut Vec<u8>) {
    // Helper to convert a field to bytes
    let field_to_bytes = |field: &CommitmentField| -> Vec<u8> {
        let mut bytes = Vec::new();
        let field_str = field.str();
        bytes.extend_from_slice(&(field_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field_str.as_bytes());
        bytes
    };

    // Helper to convert a G1 point to bytes
    let g1_to_bytes = |g1: G1| -> Vec<u8> {
        let affine = AffineG1::from_jacobian(g1).unwrap();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        affine.x().to_big_endian(&mut x).unwrap();
        affine.y().to_big_endian(&mut y).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&x);
        bytes.extend_from_slice(&y);
        bytes
    };

    // Use the helpers to append bytes to the data vector
    data.extend_from_slice(&field_to_bytes(field));
    data.extend_from_slice(&g1_to_bytes(g1));
}

#[cfg(test)]
mod test {
    use super::*;

    fn vk() -> VerificationKey {
        let vk_data = hex_literal::hex!(
            "
            000000020000001000000002000000170000000449445f31143131b30c289c43
            efe8c03ccfa57d38ea6d89d23ae31ce5714bc5daa86a768e0dc02c788ed33da5
            b66872ebf9585c8d7abc1201cd6aabd351107e383f93cd190000000449445f32
            09222ceb0abf0d5926c9d1400a7ab708cf07d19ee71a92347fb631e2b0c9375b
            1164057855c0bca748dca0f0a8ab2218edfdb0417c92e08324bc7e4c881acb35
            0000000449445f330683c3f47a10d184e4a5314cacf421b1a375e3cedc52bae2
            e35fea224407e0521b0628ad7c8b8fe407b47aa44f6a95090bed34815c57be29
            a4ebc1f0e78ea3330000000449445f342eea648c8732596b1314fe2a4d2f0536
            3f0c994e91cecad25835338edee2294f0ab49886c2b94bd0bd3f6ed1dbbe2cb2
            671d2ae51d31c1210433c3972bb6457800000003515f310559d72d10d15f649c
            19a3a54823da1de9971da1c46c036a535f8e05986b51ed0983c5a37da6ec6be1
            de6b5fcbf763b00543bbe145369b2e20cbffd928c2bc3900000003515f321f8c
            7c65c7699f8f47d53147b6fd620b44c3bb35d444ba1816c9273fed5bec600da9
            ce654018bf45bae00b147ad9f0d01ca8fce2fdc05c3c51397c58042930930000
            0003515f331857cd936f36cc4d2b2e2379760695c668b1e217d968f6566d9386
            023b48706a076ad53e1bae04e3a6b4fd89523b4461e5d8ac96084f13b031f537
            aa37c8725a00000003515f3402d6fd9e84dbe74b7531e1801405a1c292117b1a
            17fefe9de0bfd9edf1a84bf9293c6ab3c06a0669af13393a82c60a459a3b2a0b
            768da45ac7af7f2aec40fc420000000c515f41524954484d4554494322f1e3ed
            9d38a71a54c92317c905b561750db3a311c0e726f86b022476a0452d180a52fc
            e7a39700530f19446b84a44d1c725fed57ac09d9b65c98127706a27700000005
            515f415558155a0f51fec78c33ffceb7364d69d7ac27e570ae50bc180509764e
            b3fef948151c1c4720bed44a591d97cbc72b6e44b644999713a8d3c66e9054aa
            5726324c7600000003515f432b45e39cafbc9eb4b7532b63955e8331179def70
            45f3c2a32f285c041f35c85b0c1930664120ff0ebe7a46d9c19961820ff30910
            d5fc99206f2a7bcf3bdfa91b0000000a515f454c4c49505449430ad34b5e8db7
            2a5acf4427546c7294be6ed4f4d252a79059e505f9abc1bdf3ed1e5b26790a26
            eb340217dd9ad28dbf90a049f42a3852acd45e6f521f24b4900e00000003515f
            4d09553fb1dd8a17ef4b194224d94cb748f73794a8f4ca87e981ed21a536449c
            3e2065b2da0647e6320585b9a74542668a12a624e44c0cb653a6dbb82bf97c4e
            ff00000006515f534f52542cbce7beee3076b78dace04943d69d0d9e28aa6d00
            e046852781a5f20816645c2bc27ec2e1612ea284b08bcc55b6f2fd915d11bfed
            bdc0e59de09e5b28952080000000075349474d415f3106e6ea744cb25ae14df9
            c719ca45e7d4d4cd5fad40776113093355773558c90915a1b5d2ca7ba08ea089
            b540aef047f161d50e30dcfc3aad8338727de6d805e7000000075349474d415f
            320815153e6027e9e368821484e8b6a79913354843c84a82a670a26aca65c177
            d21e04ec963938a63aec007d88ba7faf34ee2ae452ad4512c830157059d5454c
            7a000000075349474d415f332e17cdcf8ce9b68c25a9f9a6dd7ec5e5741ad583
            7ccbf7e62185cdb096112a5112cf9344bd74de4361442c5dbb87d90a3ad2b480
            fb1aeab1eb85b0c44845fe87000000075349474d415f341a15b2bd5cd1f07ed3
            e286fcd0b98575a9f99b14ce89e501fc76c57701a88ff72babaa5e8cbd97086f
            2a5adbc849fe44595c1f60b1c80320d9def40c1fffd04f000000075441424c45
            5f3102c397073c8abce6d4140c9b961209dd783bff1a1cfc999bb29859cfb16c
            46fc2b7bba2d1efffce0d033f596b4d030750599be670db593af86e1923fe8a1
            bb18000000075441424c455f322c71c58b66498f903b3bbbda3d05ce8ffb571a
            4b3cf83533f3f71b99a04f6e6b039dce37f94d1bbd97ccea32a224fe2afaefbc
            bd080c84dcea90b54f4e0a858f000000075441424c455f3327dc44977efe6b37
            46a290706f4f7275783c73cfe56847d848fd93b63bf320830a5366266dd7b71a
            10b356030226a2de0cbf2edc8f085b16d73652b15eced8f5000000075441424c
            455f34136097d79e1b0ae373255e8760c49900a7588ec4d6809c90bb451005a3
            de307713dd7515ccac4095302d204f06f0bff2595d77bdf72e4acdb0b0b43969
            860d980000000a5441424c455f5459504516ff3501369121d410b445929239ba
            057fe211dad1b706e49a3b55920fac20ec1e190987ebd9cf480f608b82134a00
            eb8007673c1ed10b834a695adf0068522a000000000000
        "
        );
        VerificationKey::try_from(&vk_data[..]).unwrap()
    }

    #[test]
    fn test_vk_serialization() {
        let vk = vk();
        let data = vk.as_bytes();
        let vk2 = VerificationKey::try_from(&data[..]).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn test_vk_invalid_point() {
        let mut vk_data = vk().as_bytes();
        // from 23 to 55 is the x coordinate of Q_1 point
        for i in 23..55 {
            vk_data[i] = 0;
        }
        match VerificationKey::try_from(&vk_data[..]) {
            Err(VerificationKeyError::InvalidGroup { field, .. }) => {
                assert_eq!(field, "Q_1");
            }
            Err(e) => panic!("Test failed with unexpected error: {:?}", e),
            Ok(_) => panic!("Test failed: Expected error but got success"),
        }
    }

    #[test]
    fn test_vk_invalid_commitment_name() {
        let mut vk_data = vk().as_bytes();
        // from 20 to 22 is the commitment name size of Q_1 to Z_1
        vk_data[20] = 'Z' as u8;
        match VerificationKey::try_from(&vk_data[..]) {
            Err(VerificationKeyError::InvalidCommitmentField { value }) => {
                assert_eq!(value, "Z_1");
            }
            Err(e) => panic!("Test failed with unexpected error: {:?}", e),
            Ok(_) => panic!("Test failed: Expected error but got success"),
        }
    }

    #[test]
    fn test_vk_missing_commitment() {
        let mut vk_data = vk().as_bytes();
        // Change the commitment name size of Q_1 to Q_2
        vk_data[22] = '2' as u8;
        match VerificationKey::try_from(&vk_data[..]) {
            Err(VerificationKeyError::MissingCommitmentField { field }) => {
                assert_eq!(field, CommitmentField::Q_1);
            }
            Err(e) => panic!("Test failed with unexpected error: {:?}", e),
            Ok(_) => panic!("Test failed: Expected error but got success"),
        }
    }

    #[test]
    fn test_vk_recursion_not_supported() {
        let mut vk_data = vk().as_bytes();
        // Set contains recursive proof to true
        vk_data[1716] = 1;
        match VerificationKey::try_from(&vk_data[..]) {
            Err(VerificationKeyError::RecursionNotSupported) => {}
            Err(e) => panic!("Test failed with unexpected error: {:?}", e),
            Ok(_) => panic!("Test failed: Expected error but got success"),
        }
    }
}
