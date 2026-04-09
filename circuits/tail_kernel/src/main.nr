use l3_types::{BatchOutput, VerificationKey, PROOF_TYPE_HN_TAIL};

fn main(
    prev_kernel_inputs: call_data(0) BatchOutput,
    kernel_vk: VerificationKey,
) -> return_data BatchOutput {
    std::verify_proof_with_type(kernel_vk.key, [], [], kernel_vk.hash, PROOF_TYPE_HN_TAIL);
    prev_kernel_inputs
}
