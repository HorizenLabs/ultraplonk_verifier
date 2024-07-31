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

use serial_test::serial;
use substrate_bn::Fq;
use ultraplonk_verifier::{verify, Proof, PublicInput, VerificationKey, VerifyError};

static PROOF: Proof = hex_literal::hex!(
    "
        0520122e5831cc97fd2c08ab73ea798207d9ee8064ab401cc0722a2575f093e0
        11f9bdeccd1f282b7f6c8cffeafb68dd1a0fe3e8163e53ba0a43e38455025fc8
        2553195cf0384fd7ebf11803f2eaaf506478d2e8fbece6d5e70bc79952a301b9
        29bf436c9a99976af35c959d782432dda65712a0201c27e9db3f71b7bb924649
        0eaf72eff6b4ee9c68039e623eacd9f7444d3a15dda156595e72570558ff0405
        0a447027433433f2f6ee16df31b5fda573e71e15e94556fe242d572667769142
        228dbf9bc6ac3db74428d66baf962980cf84c1d3b1df82f703524a889ff89d04
        2991c18f11b9b5bd244393983b1515c254f98ebba40a7e0c52afb4a168844926
        0b461c4ebcc68c97054cf0a4dc2579fa0e947635fb1e85aaa01a2f1d9b1544ff
        0a746a48a25a82e11731e6268eca74ab069542d2548f914c3347cf2cfc55f6f4
        19d74326cc2990f0f0d9a451556cbf8aa20804ec381fc32398fc3d8d4e436bcb
        21f1027ad6d641421a83a58d3ddd2668bd76783700282277cda39e08b0076b3c
        1632bcb2a95126831b1d60137aa5615eae5ffc372ba388ae3b362ab6ca4d1c6f
        2e0448d1ea68deebfddc1cdd47d487f1ef03f3562f5a77ab4ea3506456ef5e73
        0b34cf5a13e43c4c9791b6516123b6ff186b581d535fe1cbf1479b4c87a69d27
        24f20ece4e85b5cd38498d5546f09269e9a2d11783e3f900723e71f0e0c9fd25
        13003baf72b53f44730e9502ab477c2c636623a6fbb28be0516fbd53efed23ca
        0191561d227eaf74f428e2398cc82aa3c7ef8c28b0c4d6797ef3a847dbe3a692
        0c2738e4de256bc2be666ac5655f18627d8d6a55dc0236c748b01fa6b6bbaf1a
        1dbaddfaffb6cbd93cf6291ac321393410f479eb01a504897aa84090e51438b4
        14ffad03ea0b5ede888cc261c5ef17a8d0c66230d3ca8187bda1baa9409d5c25
        18d7824bf3687d24c29ae6671bed170098247cba3c3baeb558acd421ef1e12c4
        1801d92a2598c149b4d0b49bfe745825d8250fdd7dd2bee51d87adf5dc075338
        102be9fe07ee810d31ed9ea589864ed080ee786cfe2518d0742ec2abb93d887a
        0f1edbcf094d526cb7dfc69fdbef0e6264caf705deecab22d098ba5feb0cef49
        273cf3382d5eeff0b840bed70abe404a67685cff8e4eb71efb513610e89956b2
        16616fd3763f3d1e408a350d0d8c2e104341e71a0786db96ff3d1601632cb4cb
        26fd0918e702d2a614c1df4949ec02dd3b6376bee29e366832b5f6a3320820a1
        2c4ecd5ee2cc9fd3bf3aadda100505e0a54d86fc5055610884889828a4e98eb6
        0cb4afa290676e7c57dde6d11b32475e173dac55c317b7d59e633a8d6391685e
        181b2fe17b4313d0e8cf43bad138ad6526ad9ca354056809d79a3e901db4b7d6
        259014e07b84ce871374e64ca1ba206539922fb121212bb22508f5b5a1f3d235
        0334727609b60f3f81f0c1ab9cc3bd2462a5a0bba1692dd2a60b8693d608ca61
        255827de1dbd0f0da3bfdf53528d6c3632f1f39a5e436682f463c526f1d28574
        2ab48b2dd18710e087d86ff6e9ab19892fc068d08bb9fda4e57884b7c93b9930
        1a44a35430efdf6d8781dc65bb07c626d7b0600b49a76a18cca2bc282ebddc85
        0445edf2b79d69aa0296578f7bafa6db2e322ba4d736e7c3880f5e1a72b6632c
        1d00d2ea7f29e6f41f11455cabe647e52812653daefa7d049b0244a7b90d2f92
        0557696f6584c414833bed735a9b9091f9beb68e0d04a1b46a1335a10f63fbf7
        25fe368d5a174da780ddd8a456ec5fc20fab26a961829bcd90269b3d60d7e611
        06195106bdd682c050e40de3caa7291a34791ce0af0be98eb527cef5bd5f037d
        0c62eee9dab6be164ac5d5d25608380a7fe8872a53ada84b04756397bd2795d0
        1accd8627fb4d30375c6a9bd8444fedea96d8cc3e341e0702e56ba1707229115
        0668e4ec136c1e7f03e1835739877a48c54b417742d25ba54c170d27ac1194c2
        1f23c9e3daf89bc9205c712469be1b52bf2b7b101a95f0e65f09f3b4f2686128
        077a6068c15378e98487193b187363ff90d7cc6078a015962e1ae4ae48bf2d8d
        2035456088dff633a102070848aa05098ab805f95063aad7410dcb3b8f15f9f3
        1e124e672d11415e9fb6db408ad2319bf39ef026e4c836f57d061c2e55bac85d
        060d7b8ffe53644c09947a2cd72bd3ea3a3e4031d776e938786fb5f61ede7b09
        0810b8f263f303bee94075cebeaf86dfcf5a8da6d75442e426de7525eca95090
        2ffdda58800b7bcf327cb66b7b30d16829c5a0c1d8ca15f40d5e61a7037020e6
        2fa29899e38a926efa814fd8bfb1e4a823b45b54fbdae41f44144f60c17d1d9b
        13aa4d5fc72193d1b8a27c5c48c69341617548a7d2fe457fceb4079d11bf8468
        1c1eccad349f47d54393ef0ca52540c810a04d62a14ca9cd77bb780e2be49da4
        121f04e2caa8fe8ce5e5d1ec501cd8e3fa5986191393a6ab33a070de60e90e86
        09f8e23296910bc95d980cf544095fdb8c887ad37a882ea9e4a01570de2b58ca
        2f8c65734b79479ba31a787a9464b002c7533fd003f58a782dad422a9cfe08c5
        1c5b4bb4ce28055aab0cb5d46b4963fc391775aece514b126eaf006dce3b0bdc
        145493024ec9cef512e59ee60289c63f95907bffb4f3e0c438de7223cc65fbaf
        1c461aee5720531d164aa92dfae84b18e848367dc87daacc90d216e33a5c29d4
        1ea147d7890daf5f82d0e1f1cfd0fc05a64e3b0843dd7908478e437629e3d7fb
        20fc74c0bafb0ba1ef571ab5a4b9acf264543f92bf3d4743fe4a7009196b8622
        2357a1a9ece867e45bdd537979a25ddf225a441d3a9d157fb5069c9c08f33449
        0c313d32f593e4cc71a51102871bcfb4d3f7829f01758164c3128beba00bb23a
        1a7c3ea0c567756ddf84d3eb071a965a0ca65b89b55c255b99f731f57f426bae
        1d79e482b6aaf1e9c6577294257e5f55b490735f84364cda04ee952dbc493c88
        18e6afcb0d0040ffddf798aecb15c105f2524fe60c3a46cae553792d8568a70f
"
);

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

fn public_inputs() -> Vec<PublicInput> {
    vec![
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000003"),
    ]
}

#[test]
#[serial]
fn should_verify_proof() {
    let pubs = public_inputs();
    let proof = PROOF;
    let vk = vk();
    
    verify(&vk, &proof, &pubs).unwrap();
}

#[test]
#[serial]
fn test_verify_invalid_pub_input() {
    let mut pubs = public_inputs();
    pubs[0][0] = 1;

    let proof = PROOF;
    let vk = vk();

    match verify(&vk, &proof, &pubs) {
        Ok(_) => panic!("Verification should have failed due to incorrect public input"),
        Err(e) => match e {
            VerifyError::VerificationFailedError => {} // Proof EC points are not on the curve
            _ => panic!("Verification failed for an unexpected reason: {:?}", e),
        },
    }
}

#[test]
#[serial]
fn test_verify_invalid_pub_input_length() {
    let mut pubs = public_inputs();
    pubs.remove(0);

    let proof = PROOF;
    let vk = vk();

    match verify(&vk, &proof, &pubs) {
        Ok(_) => panic!("Verification should have failed due to incorrect public input length"),
        Err(e) => match e {
            VerifyError::PublicInputNumberError { expected, actual } => {
                assert_eq!(expected, 2);
                assert_eq!(actual, 1);
            }
            _ => panic!("Verification failed for an unexpected reason: {:?}", e),
        },
    }
}

#[test]
#[serial]
fn test_verify_invalid_proof() {
    let pubs = public_inputs();
    let vk = vk();

    let mut proof = PROOF;
    proof[138] = 1; // Modify the proof to make it invalid

    match verify(&vk, &proof, &pubs) {
        // We have a very ambiguous situation here:
        // - If the EC proof points are on the curve but do not satisfy the constraints, the result is Ok(false).
        // - If the proof EC points are not on the curve, the result is Err(BackendError).
        // Currently, we are taking the easiest way to handle this situation, but we need to improve it.
        Ok(()) => panic!("Verification should have failed"),
        Err(VerifyError::BackendError(_)) => {} // Proof EC points are not on the curve
        Err(e) => panic!("Verification failed with an unexpected error: {:?}", e),
    }
}

#[test]
#[serial]
fn test_verify_invalid_vk() {
    let pubs = public_inputs();
    let proof = PROOF;

    let mut vk = vk();
    vk.q_1.set_x(Fq::zero()); // Modify the verification key to make it invalid

    match verify(&vk, &proof, &pubs) {
        // We have a very ambiguous situation here:
        // - If the EC proof points are on the curve but do not satisfy the constraints, the result is Ok(false).
        // - If the proof EC points are not on the curve, the result is Err(BackendError).
        // - If the verification key is invalid, the result is Err(VkError).
        // Currently, we are taking the easiest way to handle this situation, but we need to improve it.
        Ok(()) => panic!("Verification should have failed"),
        Err(VerifyError::BackendError(_)) => {} // Proof EC points are not on the curve
        Err(e) => panic!("Verification failed with an unexpected error: {:?}", e),
    }
}
