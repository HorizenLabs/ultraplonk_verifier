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
        let circuit_type = read_u32(&data[0..4]);
        if circuit_type != 2 {
            return Err(VerificationKeyError::InvalidCircuitType {
                value: circuit_type,
            });
        }

        let circuit_size = read_u32(&data[4..8]);
        let num_public_inputs = read_u32(&data[8..12]);
        let mut commitments_num = read_u32(&data[12..16]) as usize;

        let mut commitments = HashMap::new();
        let mut i = 16;
        let u32_size = 4;
        while i < data.len() && commitments_num > 0 {
            let key_size = read_u32(&data[i..i + u32_size]) as usize;
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
        let recursive_proof_public_inputs_size = read_u32(&data[i..i + u32_size]);
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
            q_1: commitments.remove(&CommitmentField::Q_1).unwrap(),
            q_2: commitments.remove(&CommitmentField::Q_2).unwrap(),
            q_3: commitments.remove(&CommitmentField::Q_3).unwrap(),
            q_4: commitments.remove(&CommitmentField::Q_4).unwrap(),
            q_m: commitments.remove(&CommitmentField::Q_M).unwrap(),
            q_c: commitments.remove(&CommitmentField::Q_C).unwrap(),
            q_arithmetic: commitments.remove(&CommitmentField::Q_ARITHMETIC).unwrap(),
            q_sort: commitments.remove(&CommitmentField::Q_SORT).unwrap(),
            q_elliptic: commitments.remove(&CommitmentField::Q_ELLIPTIC).unwrap(),
            q_aux: commitments.remove(&CommitmentField::Q_AUX).unwrap(),
            sigma_1: commitments.remove(&CommitmentField::SIGMA_1).unwrap(),
            sigma_2: commitments.remove(&CommitmentField::SIGMA_2).unwrap(),
            sigma_3: commitments.remove(&CommitmentField::SIGMA_3).unwrap(),
            sigma_4: commitments.remove(&CommitmentField::SIGMA_4).unwrap(),
            table_1: commitments.remove(&CommitmentField::TABLE_1).unwrap(),
            table_2: commitments.remove(&CommitmentField::TABLE_2).unwrap(),
            table_3: commitments.remove(&CommitmentField::TABLE_3).unwrap(),
            table_4: commitments.remove(&CommitmentField::TABLE_4).unwrap(),
            table_type: commitments.remove(&CommitmentField::TABLE_TYPE).unwrap(),
            id_1: commitments.remove(&CommitmentField::ID_1).unwrap(),
            id_2: commitments.remove(&CommitmentField::ID_2).unwrap(),
            id_3: commitments.remove(&CommitmentField::ID_3).unwrap(),
            id_4: commitments.remove(&CommitmentField::ID_4).unwrap(),
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

fn read_u32(buffer: &[u8]) -> u32 {
    ((buffer[0] as u32) << 24)
        | ((buffer[1] as u32) << 16)
        | ((buffer[2] as u32) << 8)
        | (buffer[3] as u32)
}

fn write_g1(field: &CommitmentField, g1: G1, data: &mut Vec<u8>) {
    data.extend_from_slice(&(field.str().len() as u32).to_be_bytes());
    data.extend_from_slice(field.str().as_bytes());
    let affine = AffineG1::from_jacobian(g1).unwrap();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    affine.x().to_big_endian(&mut x).unwrap();
    affine.y().to_big_endian(&mut y).unwrap();
    data.extend_from_slice(x.as_ref());
    data.extend_from_slice(y.as_ref());
}
