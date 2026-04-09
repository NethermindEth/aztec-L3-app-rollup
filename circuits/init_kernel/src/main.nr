use l3_types::{BatchOutput, VerificationKey, PROOF_TYPE_OINK};

fn main(
    app_inputs: call_data(1) BatchOutput,
    app_vk: VerificationKey,
) -> return_data BatchOutput {
    std::verify_proof_with_type(app_vk.key, [], [], app_vk.hash, PROOF_TYPE_OINK);
    app_inputs
}
