#include <barretenberg/common/serialize.hpp>
#include <barretenberg/common/wasm_export.hpp>
#include <barretenberg/ecc/curves/bn254/fr.hpp>
#include <cstddef>
#include <cstdint>

extern "C" {
const char *rust_acir_verify_proof(in_ptr acir_composer_ptr,
                                   uint8_t const *proof_buf, bool *result);
}