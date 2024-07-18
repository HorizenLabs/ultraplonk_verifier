#include "rust_bind.hpp"
#include "../acir_format/acir_to_constraint_buf.hpp"
#include "acir_composer.hpp"
#include "barretenberg/dsl/acir_format/acir_format.hpp"
#include "barretenberg/plonk/proof_system/verification_key/verification_key.hpp"
#include "barretenberg/srs/global_crs.hpp"

extern "C" {
const char *rust_acir_verify_proof(in_ptr acir_composer_ptr,
                                   uint8_t const *proof_buf, bool *result) {
  try {
    auto acir_composer =
        reinterpret_cast<acir_proofs::AcirComposer *>(*acir_composer_ptr);
    auto proof = from_buffer<std::vector<uint8_t>>(proof_buf);
    *result = acir_composer->verify_proof(proof);
    return nullptr;
  } catch (const std::exception &e) {
    return e.what(); // return the exception message
  }
}
}