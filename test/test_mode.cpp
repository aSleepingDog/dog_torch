#include "crypto/sym/block/algorithms/Rijndael.h"
#include "crypto/sym/block/sym_block_modes.h"
#include <sstream>

using dog_torch::serialize::BinaryData;
using dog_torch::crypto::Param;

using dog_torch::crypto::sym::block::algorithm::AES;
using dog_torch::crypto::sym::block::BlockCipher;

using dog_torch::crypto::sym::block::mode::create;
using dog_torch::crypto::sym::block::padding::NoPadding;

std::vector<uint64_t> error_id;
void print_error()
{
    std::cout << "error:" << error_id.size() << std::endl;
    for(auto id : error_id)
    {
        std::cout << id << ",";
    }
    std::cout << std::endl;
}
void output(
    uint64_t count, 
    const BinaryData& p0, const BinaryData& c0,
    const BinaryData& ps, const BinaryData& cs,
    const BlockCipher& cipher, const std::string& key, const std::unordered_map<std::string, Param>& params,
    const std::string& pr, const std::string& cr
)
{
    bool should_add = false;
    std::cout << "[id]" << std::endl;
    std::cout << count << std::endl;
    std::cout << "[plain]" << std::endl;
    std::cout << pr << ":Hex:lower" << std::endl;
    std::cout << "[operator]" << std::endl;
    std::cout << cipher.fmt_string() << std::endl;
    std::cout << key << ":Hex:lower" << std::endl;
    for(auto& [k,v] : params)
    {
        std::cout << k << ":";
        if(v.index()==0)
        {
            std::cout << std::boolalpha << std::get<0>(v) << std::endl;
        }
        else if(v.index()==1)
        {
            std::cout << std::get<1>(v) << std::endl;
        }
        else if(v.index()==2)
        {
            std::cout << std::get<2>(v) << std::endl;
        }
        else if(v.index()==3)
        {
            std::cout << std::get<3>(v).to_hex_string(false) << std::endl;
        }
    }
    std::cout << "[crypt]" << std::endl;
    std::cout << cr << ":Hex:lower" << std::endl;
    std::cout << c0.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << cs.to_hex_string(false) << ":Hex:lower" << std::endl;
    //std::cout << csp.to_hex_string(false) << ":Hex:lower" << std::endl;
    if (c0 != BinaryData{ cr,BinaryData::Type::Hex })
    {
        should_add = true;
    }
    if (cs != BinaryData{ cr,BinaryData::Type::Hex })
    {
        should_add = true;
    }
    //if (csp != BinaryData{ cr,BinaryData::Type::Hex })
    //{
    //    should_add = true;
    //}
    std::cout << "[plain]" << std::endl;
    std::cout << p0.to_hex_string(false) << ":Hex:lower" << std::endl;
    std::cout << ps.to_hex_string(false) << ":Hex:lower" << std::endl;
    //std::cout << psp.to_hex_string(false) << ":Hex:lower" << std::endl;
    if (p0 != BinaryData{ pr,BinaryData::Type::Hex })
    {
        should_add = true;
    }
    if (ps != BinaryData{ pr,BinaryData::Type::Hex })
    {
        should_add = true;
    }
    //if (psp != BinaryData{ pr,BinaryData::Type::Hex })
    //{
    //    should_add = true;
    //}
    if (should_add)
    {
        error_id.push_back(count);
    }
    std::cout << std::boolalpha << !should_add << std::endl;
    std::cout << std::endl;
}
void w(
    uint64_t count, 
    const std::string& key, const std::string& mode, const std::unordered_map<std::string, Param>& params, 
    const std::string& pr, const std::string& cr)
{
    using dog_torch::async::thread::PauseableChannel;

    auto mode_p = create(mode,NoPadding(),params);
    BlockCipher cipher = BlockCipher(BinaryData{key,BinaryData::Type::Hex}, AES(128),*mode_p);
    cipher.init();

    auto prb = BinaryData{ pr,BinaryData::Type::Hex };
    auto c0 = cipher.encrypt(prb);
    auto pss = std::stringstream(prb.to_string(), std::ios::in | std::ios::binary);
    auto c0ss = std::stringstream(std::ios::out | std::ios::binary);
    cipher.encrypt_stream(pss, pss.view().size(), c0ss);
    auto c0ssb = BinaryData{ c0ss.str(),BinaryData::Type::UTF8 };

    auto crb = BinaryData{ cr,BinaryData::Type::Hex };
    auto p0 = cipher.decrypt(crb);
    auto css = std::stringstream(crb.to_string(), std::ios::in | std::ios::binary);
    auto p0ss = std::stringstream(std::ios::out | std::ios::binary);
    cipher.decrypt_stream(css, css.view().size(), p0ss);
    auto p0ssb = BinaryData{ p0ss.str(),BinaryData::Type::UTF8 };

    //output(count, p0, c0, p0ssb, c0ssb, p0ssbp, c0ssbp, cipher, key, params, pr, cr);
    output(count, p0, c0, p0ssb, c0ssb, cipher, key, params, pr, cr);
}
void outputs(
    uint64_t count,
    const std::string& p0, const std::string& c0,
    const std::string& ps, const std::string& cs,
    //const std::string& psp, const std::string& csp,
    const BlockCipher& cipher, const std::string& key, const std::unordered_map<std::string, Param>& params,
    const std::string& pr, const std::string& cr
)
{
    bool should_add = false;
    std::cout << "[id]" << std::endl;
    std::cout << count << std::endl;
    std::cout << "[plain]" << std::endl;
    std::cout << pr << ":bin" << std::endl;
    std::cout << "[operator]" << std::endl;
    std::cout << cipher.fmt_string() << std::endl;
    std::cout << key << ":Hex:lower" << std::endl;
    for (auto& [k, v] : params)
    {
        std::cout << k << ":";
        if (v.index() == 0)
        {
            std::cout << std::boolalpha << std::get<0>(v) << std::endl;
        }
        else if (v.index() == 1)
        {
            std::cout << std::get<1>(v) << std::endl;
        }
        else if (v.index() == 2)
        {
            std::cout << std::get<2>(v) << std::endl;
        }
        else if (v.index() == 3)
        {
            std::cout << std::get<3>(v).to_hex_string(false) << std::endl;
        }
    }
    std::cout << "[crypt]" << std::endl;
    std::cout << cr << ":bin" << std::endl;
    std::cout << c0 << ":bin" << std::endl;
    std::cout << cs << ":bin" << std::endl;
    //std::cout << csp << ":bin" << std::endl;
    if (c0 != cr)
    {
        should_add = true;
    }
    if (cs != cr)
    {
        should_add = true;
    }
    //if (csp != cr)
    //{
    //    should_add = true;
    //}
    std::cout << "[plain]" << std::endl;
    std::cout << p0 << ":bin" << std::endl;
    std::cout << ps << ":bin" << std::endl;
    //std::cout << psp << ":bin" << std::endl;
    if (p0 != pr)
    {
        should_add = true;
    }
    if (ps != pr)
    {
        should_add = true;
    }
    //if (psp != pr)
    //{
    //    should_add = true;
    //}
    if (should_add)
    {
        error_id.push_back(count);
    }
    std::cout << std::boolalpha << !should_add << std::endl;
    std::cout << std::endl;
}
void ws(
    uint64_t count,
    const std::string& key, const std::string& mode, const std::unordered_map<std::string, Param>& params,
    std::string pr, std::string cr)
{
    auto mode_p = create(mode, NoPadding(), params);
    BlockCipher cipher = BlockCipher(BinaryData{ key,BinaryData::Type::Hex }, AES(128), *mode_p);
    cipher.init();

    using dog_torch::async::thread::PauseableChannel;

    uint64_t pr_s = pr.size();
    uint64_t cr_s = cr.size();

    while (pr.size() % 8)
    {
        pr += "0";
    }
    while (cr.size() % 8)
    {
        cr += "0";
    }

    auto prb = BinaryData{ pr,BinaryData::Type::Binary };
    auto c0 = cipher.encrypt(prb);
    auto ps = std::stringstream(prb.to_string(), std::ios::in | std::ios::binary);
    auto c0ss = std::stringstream(std::ios::out | std::ios::binary);
    cipher.encrypt_stream(ps, ps.view().size(), c0ss);
    auto c0ssb = BinaryData{ c0ss.str(),BinaryData::Type::UTF8 }.to_bin_string().substr(0, cr_s);

    auto crb = BinaryData{ cr,BinaryData::Type::Binary };
    auto p0 = cipher.decrypt(crb);
    auto cs = std::stringstream(crb.to_string(), std::ios::in | std::ios::binary);
    auto p0ss = std::stringstream(std::ios::out | std::ios::binary);
    cipher.decrypt_stream(cs, cs.view().size(), p0ss);
    auto p0ssb = BinaryData{ p0ss.str(),BinaryData::Type::UTF8 }.to_bin_string().substr(0, pr_s);


    outputs(count,
        p0.to_bin_string().substr(0, pr_s), c0.to_bin_string().substr(0, cr_s),
        p0ssb, c0ssb,
        //p0ssbp, c0ssbp,
        cipher, key, params,
        prb.to_bin_string().substr(0, pr_s), crb.to_bin_string().substr(0, cr_s)
    );
}
uint64_t id()
{
    static uint64_t c = 0;
    return c++;
}
int main()
{
	std::cout << "test set from " << R"<url>(https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip)<url>" << std::endl;

    //ECB
    w(id(), "edfdb257cb37cdf182c5455b0c0efebb", "ECB", {}, "1695fe475421cace3557daca01f445ff", "7888beae6e7a426332a7eaa2f808e637");
    w(id(), "7723d87d773a8bbfe1ae5b081235b566", "ECB", {}, "1b0a69b7bc534c16cecffae02cc5323190ceb413f1db3e9f0f79ba654c54b60e", "ad5b089515e7821087c61652dc477ab1f2cc6331a70dfc59c9ffb0c723c682f6");
    w(id(), "280afe063216a10b9cad9b2095552b16", "ECB", {}, "6f172bb6ec364833411841a8f9ea2051735d600538a9ea5e8cd2431a432903c1d6178988b616ed76e00036c5b28ccd8b", "4cc2a8f13c8c7c36ed6a814db7f26900c7e04df49cbad916ce6a44d0ae4fe7edc0b402794675b3694933ebbc356525d8");
    w(id(), "ef60fb1400c83936414a25651eb51a1b", "ECB", {}, "593559318cc66bf695e49feb42794bdfb66bce895ec222ca2609b133ecf66ac7344d13021e01e11a969c4684cbe20abae2b19d3ceb2cacd41419f21f1c865149", "3ea6f4305217bd47eebe773da4b578549cac744c00cbd8f9d596d38010304bd850cc2f4b19a91c2e022eabf100266185ca2705127815dfd46efbe4ecd46a3058");
    w(id(), "c5805cd1c4a7b98a715badb709720bf4", "ECB", {}, "84f809fc5c84652376cc0df10095bc00b9f0547fa91a2d3310a0adbc9cc6191ade2aaa6fffa5e406af7223955f9277bfb06eb1dd2bbfbefe32ab342c36302bf22bc64e1b394032bbb5f4e6744f1bcbf2", "a6dc096bc21b0658e416a0f679fefc6e958e9c56e3ce04fdf6e392c2db770a60d9523c255925e14a3e02a1002bf3875c2e501bac618bee1f55f9850454854eef9d693d90937cc8387b6f4c4414e2080b");
    w(id(), "4c35be028e1475278346eae531cbee5c", "ECB", {}, "7adcf4a494f6b09790c82c8bb97db62c5d3fa4032f06dfeceaad9ecb374b747bd1c08d07e78e351dc2eb99bfa714d23cffe31f5fb5a472e6e0252f35a20c304c4f6d0cf7d29c99444d40af3a00a92fc86c6444fcb80ce9765362ac1bdba0b10e", "22217953f71932ab4360d97ef495081559f1fcb09caca41fa0c65f7b1792b560eabe18f3b3b06ef80c41886f24c5d6d32d20427e83d8b5564d9ac7435a2842c1cf7c6fcc229eb7f518d3e0167d510efbaee39a0438fc800eb6acfc203c93280c");
    w(id(), "00cc73c990d376b82246e45ea3ae2e37", "ECB", {}, "37a1205ea929355d2e4ee52d5e1d9cda279ae01e640287ccb153276e7e0ecf2d633cf4f2b3afaecb548a2590ce0445c6a168bac3dc601813eb74591bb1ce8dfcd740cdbb6388719e8cd283d9cc7e736938240b410dd5a6a48ba49dd2066503e63ab592ffdf3be49e7d2de74f82158b8c", "c88e03383ba9da6f982c057fe92c0bb3ed5b9cd18295a100e13a4e12d440b919bbb8b221abead362902ce44d30d0b80e56bee1f66a7d8de0b1e1b4dbf76c90c1807a3bc5f277e9814c82ab120f7e10217dfdf6092ce4958f8906c5e32279c6537dd1fbae20cb7a1d9f89d0490b6aefc1");
    w(id(), "0a53aa7a3e4a4f364e8c6c7224af5501", "ECB", {}, "eaf1760c0f25310dada6debeb966304db7a9f1b2d1c3af922623b263649031d299b3c56146d61d55b6ebf4cf8dd04039a4d1ace3146f49ee915f806afad64cbb2d04a64120de40382e2175dcae9480d1ca8dedc38fb64e4a40112f10f03a4c354fed01f2c5c7017dbd514b2d443a5adfd2e49c986723266cda41a69e6e459908", "5ece70a44da41bc7cfb9b582ea9ce0980030ec4af331e76499961f88860aa0554aba3ecbf77ca4293a3fee854a2caf3ae800343fb4521388b16b6dc599b3d60bf82777f98e1a8d04ab9cd54dd9a248095795d4dfe4858bfd9a05f54c795bb086e15f7c22228184ec66a9ca10b1cf71a6bb9303c5cd1dcc056460a86df651f053");
    w(id(), "b80bcc929052cb5450479442e2b809ce", "ECB", {}, "8177d79c8f239178186b4dc5f1df2ea7fee7d0db535489ef983aefb3b2029aeba0bb2b46a2b18c94a1417a33cbeb41ca7ea9c73a677fccd2eb5470c3c500f6d3f1a6c755c944ba586f88921f6ae6c9d194e78c7233c406126633e144c3810ad23ee1b5af4c04a22d49e99e7017f74c2309492569ff49be17d2804920f2ac5f514d13fd3e7318cc7cf80ca5101a465428", "5befb3062a7a7246af1f77b0ec0ac614e28be06ac2c81b19e5a0481bf160f9f2bc43f28f6548787639e4ce3e0f1e95475f0e81ceb793004c8e46670ebd48b866d5b43d104874ead4be8a236bf90b48f862f7e252dec4475fdbb841a662efcd25ed64b2910e9baaea9466e413a4241438b31df0bd3df9a16f4641636754e259861728aa7ddf435cc51f54f79a1db25f52");
    w(id(), "ebea9c6a82213a00ac1d22faea22116f", "ECB", {}, "451f45663b44fd005f3c288ae57b383883f02d9ad3dc1715f9e3d6948564257b9b06d7dd51935fee580a96bbdfefb918b4e6b1daac809847465578cb8b5356ed38556f801ff7c11ecba9cdd263039c15d05900fc228e1caf302d261d7fb56cee663595b96f192a78ff4455393a5fe8162170a066fdaeac35019469f22b3470686bced2f007a1a2e43e01b4562caaa502ed541b8205874ec1ffb1c8b255766942", "01043053f832ef9b911ed387ba577451e30d51d4b6b11f319d4cd539d067b7f4f9b4f41f7f3d4e920c57cbe2b5e1885aa66203ae493e93a1df63793a9563c176bc6775dd09cc9161e278a01beb8fd8a19200326bd95abc5f716768e34f90b50523d30fdabb103a3bc020afbbb0cb3bd2ad512a6fea79f8d64cef347458dec48be89451cb0b807d73593f273d9fc521b789a77524404f43e00f20b3b77b938b1a");
    w(id(), "54b760dd2968f079ac1d5dd20626445d", "ECB", {}, "46f2c98932349c338e9d67f744a1c988", "065bd5a9540d22d5d7b0f75d66cb8b30");
    w(id(), "bce4c486cc4a12622b9147df9bca452c", "ECB", {}, "8c8e6ed8a6bdb3baabec78189b7d61010d6d168de2c08ec56f9b9c004a191e21", "76fa67e121894dbc2ad85ae7f9c5c44d14ccee5b87d5e7708950338f5c84cf58");
    w(id(), "279161759d29e92dc8f1fafd8d45533d", "ECB", {}, "8838058bd98072b72fd75641edb216301fee8323ff8c4ba18ee6a4623c2fdeb3df5f8a240a8e7e6d5ae15444614f41fb", "1ce69ab7624fed511fb42b8fb639f566d72783f9ab49801651961b048e0f5b7cc0ebb2f514f2d625f927ccc4d5a94593");
    w(id(), "9ba852520c9fd1eb367b6ad2aed07abd", "ECB", {}, "6061df5bcd421fabdb5235fc032502650448fd8233a0237c5f6f249a63d7db3e4283ac9a8684a363ef64e760c5886564659da619466851568b32091df5516f57", "6c53489f6a4bd0f7cd15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7ccd62376d5ebb41");
    w(id(), "cd6a33abb95d7ab92980f9c2b810c90f", "ECB", {}, "3f098ae7e7524ddb556403c5d3d0b10e5db6c324843ca54a47e34ad9bdbccc93a645e96f2e98651751f0f1a697398ea801a69079c1808b6a8e3bb02a4cf3292f1a7a05b954571339f7899f9aaa2ae1e9", "33cb1a98ce4be97f5b222aa861c945643f372687cbf7f8193a7d304e40baceb877eedfbc05be47437a86bdb1f7f0171b95c6c8b50404a7897332f26fb0f0923991d3a02e926f29babfb52e63d580efff");
    w(id(), "ff71b9f6311a44072ddb1a77488c4870", "ECB", {}, "3dfe918048f4c0b0b22fbc55e5af751cf3e6ce348eb9a888795033f6dd216afbea65fc8df41c0ce6c7316a8183d36060bf19709fe2bec6d13bbdf1a434cc5b8f10aadb368c269d2dc4474a1f8112640fe52803b1883cb7756743100a758dd862", "19d76b386a7715dec7aad8bb01d126c7385a4387f087faec67718f78274cf4a2d7ec3f7c56885c930bbfff1676d8dd3b0b4e1cdf418c086de6f50700b527cfcc2a81d6ba95e30a526eb4c3dee82af6ccc8c5ab55781db15c57de90995411bff6");
    w(id(), "8ec6a5a054fea2fc8dafb5939a4bd788", "ECB", {}, "6e19cec775595c2f768de3bda3682fb4026ed1889fc3de11bc45a2a3e2b22694ddaab3274c81b29204fa034eedac564a7dfe27aabb6ff420f9aa5abadf15c74676efeabd96a7ff2491813ba53cb5ab76eacd37255a28daecbbe580f5eb77f9bc0339e0da59b2b307f52974b6182cb106", "4d6f972946a2e4ca05bfbeecd00535ece6c81ed963c4167063b1c34b6a185d5504646d81a83cd5bce2101120b2f2bc6a2fa856ae6fff4449ab6218189faa13e73038e82c5141c3f6276a8a206b9563ca11fa76092779f4deff2e58659047ed4f1a129092095ab75f1cf4b255c69531f4");
    w(id(), "b53e54b1b09f78abcd6afac1f7e7cda9", "ECB", {}, "398db04b45a724393e4baec86a220f22358df1bbf0cab278dcfecf7a3f8f6275ef45ed9f039bc1f5030c3a0c245fbb6ea0bff3e2da0859ac498db6624a572023de7c221bf3567f51e98947970dfc581b3ca670ab92953d3bdd97dbf5d6bef8aa2f31500d221198ed9f23b049eaeed67683083034b4a5a82a0e49319e368c6f55", "447557bd1561b09a082cabdbf49b0612b46c9793db3c987aa4a843ef28b39fa8d46799b019c0566765c5c8cb53f87ff51ff0c2e65c45df84e9acbfe02163bdba52d0b847706567320bc6ede07f2eaef86b0f602364f86510eabc58bc9ad1e6f0a6f6df0b83188c01e17744a4e0053a22810e99cf5a1ed3258f203509fdc3c050");
    w(id(), "9e79b681c57d7feb7db7e8a6ad41382c", "ECB", {}, "a2e19c08fa204640b1bc73beac58f81a7923f3ef2a0affcf1568c9179d816cf1bd16b79418f0266f0ff904e06045f276df187ed72b8f6641b065b854a7d3f152b8e153cd77ec605e5b75454245745dc0e0dcfc616f5246f868b6ee5a1df56c4906c5c34bc42309d370733e50d9a1addc3f37cbe4b331ac7d3a920c794484a16b05599f46f42046a6dc9063b1d5a8ae1f", "fa2e97bed2f0b76ed2f8c1275f6d50ecfc1131240622ba9da17e5dd0f20a7d678f537ffc33762524b73e17ac3d8dc322affd679768c66ca430e3f6ab6e70b95f99570e87f02b46ff6b543efff16d339fcbead89b59fea65403bc7418737c47a301806be66fd7c307d7825da8e1d6496c3921acb7419010b60350fea069f4cf3bb017bfa11a424344e3109d30778fad90");
    w(id(), "44f0ee626d0446e0a3924cfb078944bb", "ECB", {}, "9c29eecb2de04254fafb896a994102d1da30ddb49d82728eb23dbd029901e9b75b3d0aee03f7a05f6c852d8fada0b5c28e8c9aed334fad11829df3dfadc5c2e471eb41af9e48a8a465e03d5ebdb0216915081f3b5a0ebb2308dfc2d28e5a8ba3f32adae4c3575921bc657b63d46ba5a618880ee9ad8af3fba5643a5026facd7d667ce599327f936cdda7e1bb742a33a019990b76be648a6ec725daed540ed9e7", "931b2f5f3a5820d53a6beaaa6431083a3488f4eb03b0f5b57ef838e1579623103bd6e6800377538b2e51ef708f3c4956432e8a8ee6a34e190642b26ad8bdae6c2af9a6c7996f3b6004d2671e41f1c9f40ee03d1c4a52b0a0654a331f15f34dce4acb96bd6507815ca4347a3de11a311b7de5351c9787c4538158e28974ffa83d8296dfe9cd09cd87f7bf4f54d97d28d4788799163408323943b3e72f5eab66c1");
    //CBC
    w(id(), "1f8e4973953f3fb0bd6b16662e9a3c17", "CBC", { { "iv",BinaryData("2fe2b333ceda8f98f4a99b40d2cd34a8",BinaryData::Type::Hex) } }, "45cf12964fc824ab76616ae2f4bf0822", "0f61c4d44c5147c03c195ad7e2cc12b2");
    w(id(), "0700d603a1c514e46b6191ba430a3a0c", "CBC", { { "iv",BinaryData("aad1583cd91365e3bb2f0c3430d065bb",BinaryData::Type::Hex) } }, "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91", "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00");
    w(id(), "3348aa51e9a45c2dbe33ccc47f96e8de", "CBC", { { "iv",BinaryData("19153c673160df2b1d38c28060e59b96",BinaryData::Type::Hex) } }, "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599", "d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726ded97818e1f127a28d72db5652749f0c6afee5");
    w(id(), "b7f3c9576e12dd0db63e8f8fac2b9a39", "CBC", { { "iv",BinaryData("c80f095d8bb1a060699f7c19974a1aa0",BinaryData::Type::Hex) } }, "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e", "19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467");
    w(id(), "b6f9afbfe5a1562bba1368fc72ac9d9c", "CBC", { { "iv",BinaryData("3f9d5ebe250ee7ce384b0d00ee849322",BinaryData::Type::Hex) } }, "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1", "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9");
    w(id(), "bbe7b7ba07124ff1ae7c3416fe8b465e", "CBC", { { "iv",BinaryData("7f65b5ee3630bed6b84202d97fb97a1e",BinaryData::Type::Hex) } }, "2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187", "3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe");
    w(id(), "89a553730433f7e6d67d16d373bd5360", "CBC", { { "iv",BinaryData("f724558db3433a523f4e51a5bea70497",BinaryData::Type::Hex) } }, "807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a386c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625", "406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb223828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f16635caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a");
    w(id(), "c491ca31f91708458e29a925ec558d78", "CBC", { { "iv",BinaryData("9ef934946e5cd0ae97bd58532cb49381",BinaryData::Type::Hex) } }, "cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e5152649f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1bd4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbca6c7f335cfce9b45cb9d", "7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d07666126fb761f84078f2");
    w(id(), "f6e87d71b0104d6eb06a68dc6a71f498", "CBC", { { "iv",BinaryData("1c245f26195b76ebebc2edcac412a2f8",BinaryData::Type::Hex) } }, "f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e479ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e38244509f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729", "b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f490f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93eed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b6984353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365");
    w(id(), "2c14413751c31e2730570ba3361c786b", "CBC", { { "iv",BinaryData("1dbbeb2f19abb448af849796244a19d7",BinaryData::Type::Hex) } }, "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd206225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f", "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b");
    w(id(), "6a7082cf8cda13eff48c8158dda206ae", "CBC", { { "iv",BinaryData("bd4172934078c2011cb1f31cffaf486e",BinaryData::Type::Hex) } }, "940bc76d61e2c49dddd5df7f37fcf105", "f8eb31b31e374e960030cd1cadb0ef0c");
    w(id(), "625eefa18a4756454e218d8bfed56e36", "CBC", { { "iv",BinaryData("73d9d0e27c2ec568fbc11f6a0998d7c8",BinaryData::Type::Hex) } }, "360dc1896ce601dfb2a949250067aad96737847a4580ede2654a329b842fe81e", "5d6fed86f0c4fe59a078d6361a142812514b295dc62ff5d608a42ea37614e6a1");
    w(id(), "fd6e0b954ae2e3b723d6c9fcae6ab09b", "CBC", { { "iv",BinaryData("f08b65c9f4dd950039941da2e8058c4e",BinaryData::Type::Hex) } }, "a206385945b21f812a9475f47fddbb7fbdda958a8d14c0dbcdaec36e8b28f1f6ececa1ceae4ce17721d162c1d42a66c1", "e29e3114c8000eb484395b256b1b3267894f290d3999819ff35da03e6463c186c4d7ebb964941f1986a2d69572fcaba8");
    w(id(), "7b1ab9144b0239315cd5eec6c75663bd", "CBC", { { "iv",BinaryData("0b1e74f45c17ff304d99c059ce5cde09",BinaryData::Type::Hex) } }, "b968aeb199ad6b3c8e01f26c2edad444538c78bfa36ed68ca76123b8cdce615a01f6112bb80bfc3f17490578fb1f909a52e162637b062db04efee291a1f1af60", "d3f89b71e033070f9d7516a6cb4ea5ef51d6fb63d4f0fea089d0a60e47bbb3c2e10e9ba3b282c7cb79aefe3068ce228377c21a58fe5a0f8883d0dbd3d096beca");
    w(id(), "36466b6bd25ea3857ea42f0cac1919b1", "CBC", { { "iv",BinaryData("7186fb6bdfa98a16189544b228f3bcd3",BinaryData::Type::Hex) } }, "999983467c47bb1d66d7327ab5c58f61ddb09b93bd2460cb78cbc12b5fa1ea0c5f759ccc5e478697687012ff4673f6e61eecaeda0ccad2d674d3098c7d17f887b62b56f56b03b4d055bf3a4460e83efa", "9ed957bd9bc52bba76f68cfbcde52157a8ca4f71ac050a3d92bdebbfd7c78316b4c9f0ba509fad0235fdafe90056ad115dfdbf08338b2acb1c807a88182dd2a882d1810d4302d598454e34ef2b23687d");
    w(id(), "89373ee6e28397640d5082eed4123239", "CBC", { { "iv",BinaryData("1a74d7c859672c804b82472f7e6d3c6b",BinaryData::Type::Hex) } }, "45efd00daa4cdc8273ef785cae9e944a7664a2391e1e2c449f475acec0124bbc22944331678617408a1702917971f4654310ffb9229bec6173715ae512d37f93aaa6abf009f7e30d65669d1db0366b5bce4c7b00f871014f5753744a1878dc57", "1bcba44ddff503db7c8c2ec4c4eea0e827957740cce125c1e11769842fa97e25f1b89269e6d77923a512a358312f4ba1cd33f2d111280cd83e1ef9e7cf7036d55048d5c273652afa611cc81b4e9dac7b5078b7c4716062e1032ead1e3329588a");
    w(id(), "bab0cceddc0abd63e3f82e9fbff7b8aa", "CBC", { { "iv",BinaryData("68b9140f300490c5c942f66e777eb806",BinaryData::Type::Hex) } }, "c5585ff215bbb73ba5393440852fb199436de0d15e55c631f877670aa3eda9f672eb1f876f09544e63558436b8928000db2f02a5ad90f95b05ac4cf49e198e617e7678480fdf0efacc6aae691271e6cdd3541ebf719a1ccaedb24e2f80f92455dd5910cb5086b0960a3942ec182dcbd7", "c65b94b1f291fa9f0600f22c3c0432c895ad5d177bcccc9ea44e8ec339c9adf43855b326179d6d81aa36ef59462fd86127e9d81b0f286f93306bf74d4c79e47c1b3d4b74edd3a16290e3c63b742e41f20d66ceee794316bb63d3bd002712a1b136ba6185bd5c1dab81b07db90d2af5e5");
    w(id(), "9c702898efa44557b29ed283f5bc0293", "CBC", { { "iv",BinaryData("cec6e1b82e8b2a591a9fa5ff1cf5cc51",BinaryData::Type::Hex) } }, "1d1f8d81bdc3e2c7cb057f408e6450000c5aaed3260ff1e87fbb6f324df6887ffd8f78d7e2a04c9ed9deda9d64482d2b002f4a2b78d8b4f691875c8295d4a64b22257ceaf713ed2f4b92530d7ad7151d629acda882b4829577a43990b0948c1149c22fe4273656d1b08833930e8b06709a94579a78fc220f7057bbc1fa9f6563", "ba9f646755dacc22911f51d7de2f7e7cb0bc0b75257ea44fe883edb055c7c28ede04c3a0adcb10128ad4517d0093fa16bb0bcd2635e7a0ba92c7609bc8d8568002a7a983473724d256513aa7d51b477aabec1975ab5faf2872a6407e922180eff02f1ef86a4591c8bd3d143da6f0ef0e4806f94ace0d5b0151c99640fccbc843");
    w(id(), "5674636dbdb38f705f0b08c372ef4785", "CBC", { { "iv",BinaryData("3f20ce0509b57420d53b6be4d0b7f0a9",BinaryData::Type::Hex) } }, "6d40fd2f908f48ce19241b6b278b1b1676dffd4a97ce9f8a1574c33bc59237deb536bee376fd6c381e6987700e39283aa111cf1a59f26fae6fb6700bf012646a2ab80239bf5e1632329043aa87d7911978b36523a2bc0bed9a9737ccf7a00baa2f3822b4e9e742e168e7069290705fed2eb63aa044b78f97dd33a8d6b24741ec1fd8c8db79d93b884e762dba0f406961", "198351f453103face6655666fe90bdbd9630e3733b2d66c013a634e91f2bf015bd2d975d71b26322e44defa32d4e9dce50363557046ece08ba38f258dae5fd3e5049c647476c81e73482e40c171d89f9fea29452caf995733589b0061464fbd5dabe27dc5ea463a3deeb7dcb43664ae6a65c498c143883ab8e83b51e5410b181647602443dc3cfffe86f0205398fa83c");
    w(id(), "97a1025529b9925e25bbe78770ca2f99", "CBC", { { "iv",BinaryData("d4b4eab92aa9637e87d366384ed6915c",BinaryData::Type::Hex) } }, "e8b89150d8438bf5b17449d6ed26bd72127e10e4aa57cad85283e8359e089208e84921649f5b60ea21f7867cbc9620560c4c6238db021216db453c9943f1f1a60546173daef2557c3cdd855031b353d4bf176f28439e48785c37d38f270aa4a6faad2baabcb0c0b2d1dd5322937498ce803ba1148440a52e227ddba4872fe4d81d2d76a939d24755adb8a7b8452ceed2d179e1a5848f316f5c016300a390bfa7", "22cdc3306fcd4d31ccd32720cbb61bad28d855670657c48c7b88c31f4fa1f93c01b57da90be63ead67d6a325525e6ed45083e6fb70a53529d1fa0f55653b942af59d78a2660361d63a7290155ac5c43312a25b235dacbbc863faf00940c99624076dfa44068e7c554c9038176953e571751dfc0954d41d113771b06466b1c8d13e0d4cb675ed58d1a619e1540970983781dc11d2dd8525ab5745958d615defda");
    //CFBb 1
    ws(id(), "ca705ee6847bcf17a6396fec473135cf", "CFBb", { { "iv",BinaryData("c81b8a75c1a4d5243cd889540c8e3622",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0", "0");
    ws(id(), "cdef9d0661bae4738d1a58a2a6228b66", "CFBb", { { "iv",BinaryData("4dbbdcaa59f363c92a3b9843ad20e2b7",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "11", "00");
    ws(id(), "1e3b6e224a79a5e40e4a1c084bdad9cb", "CFBb", { { "iv",BinaryData("4c55a0bae99ab9f4e9cdcb0238b8c525",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "111", "101");
    ws(id(), "8a31587e6bf41d46087ba8800f912fd6", "CFBb", { { "iv",BinaryData("0905779f9d72f322721bc48ae7efee5a",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "1101", "0010");
    ws(id(), "5c113f7f55448f1929241f185c314019", "CFBb", { { "iv",BinaryData("42613bf61f0bbe30668e69d4d094d171",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "10000", "10110");
    ws(id(), "258cc0daa17c0af0c137c82cea609fee", "CFBb", { { "iv",BinaryData("604ccded57a64243752e4d80e5ac9e65",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "110101", "110101");
    ws(id(), "5a22f2b7b9f1fc7337a1ac62aeb64842", "CFBb", { { "iv",BinaryData("62b10fc4299ccc50752724a5a9343bde",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0100100", "0001101");
    ws(id(), "250d3ce76fae1953617143bac2d0dffa", "CFBb", { { "iv",BinaryData("c13561f6d97834e515ee99a4510ff494",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "00100010", "00001011");
    ws(id(), "fb79de45bfef77cc723f919de28b1900", "CFBb", { { "iv",BinaryData("e26066c58906e341736c8524b5252137",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "101100010", "110011001");
    ws(id(), "68dedc2e02194fb0349db1fa43ec9232", "CFBb", { { "iv",BinaryData("56399132416f426516e833bfc7d79b25",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "1100000011", "0101110111");
    ws(id(), "096225a638f36262e9707ba8a4d2d654", "CFBb", { { "iv",BinaryData("a934ecacea224e4136589dc0b3344f17",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0", "1");
    ws(id(), "89750356998f21fed95d4429e2ebdfcb", "CFBb", { { "iv",BinaryData("112a658d3caa1efb65137675b047dd7b",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "10", "00");
    ws(id(), "1c81130e3bcb8605a6d6b9ad2a12ee90", "CFBb", { { "iv",BinaryData("d8ce9b563322b2142be1bd661f8497c6",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "101", "110");
    ws(id(), "d65aea137761558d1b8400952c154037", "CFBb", { { "iv",BinaryData("fc826c2f95c7b1613c59a7c09a105099",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0111", "1110");
    ws(id(), "0cc56e694732100722bf50d25d7b0efd", "CFBb", { { "iv",BinaryData("c88d92361e1b723587ef0a700dfa597b",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "01110", "00111");
    ws(id(), "42f32669fd5b5eaf9e61d5ef32e9af4a", "CFBb", { { "iv",BinaryData("3ff46b35773df98f9c7b7c8c5486fe5e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "001001", "010111");
    ws(id(), "bf84d99ef4312bd9ef79e828b06da94f", "CFBb", { { "iv",BinaryData("cb7be6e41d0ae71337fd860b0a95d139",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0010111", "1110011");
    ws(id(), "0b3a695805c4a84775f5c8051ba5173f", "CFBb", { { "iv",BinaryData("4ace89f78057ad8b006327880a8350b1",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "11110000", "10011010");
    ws(id(), "493509b56a92f14040eb9b66a188bc57", "CFBb", { { "iv",BinaryData("7251c5e5fd763b1016a1989ad2a045da",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "110011011", "110000110");
    ws(id(), "822f3996006d92913f6aba0561c799c9", "CFBb", { { "iv",BinaryData("e2112d0f3bed28b3cc05bd977549723a",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "0000110111", "1011111011");
    //CFB 1
    w(id(), "c57d699d89df7cfbef71c080a6b10ac3", "CFB", { { "iv",BinaryData("fcb2bc4c006b87483978796a2ae2c42e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "61", "24");
    w(id(), "0d8f3dc3edee60db658bb97faf46fba3", "CFB", { { "iv",BinaryData("e481fdc42e606b96a383c0a1a5520ebb",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "aacd", "5066");
    w(id(), "c8fe9bf77b930f46d2078b8c0e657cd4", "CFB", { { "iv",BinaryData("f475c64991b20eaee183a22629e21e22",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "c90635", "d27691");
    w(id(), "280cf81af5cc7e7363579c1da03390e6", "CFB", { { "iv",BinaryData("5d6cf4722d0e21f1d9ced53a0e36c342",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "b2a22ced", "73f3aebf");
    w(id(), "5d5e7f20e0a66d3e09e0e5a9912f8a46", "CFB", { { "iv",BinaryData("052d7ea0ad1f2956a23b27afe1d87b6b",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "b84a90fc6d", "1a9a61c307");
    w(id(), "ec89fb348787cf902ca973c47081438d", "CFB", { { "iv",BinaryData("528fe95c711bd13f37bc52cc9e96d45c",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "14253472e99d", "cfc247e33a3b");
    w(id(), "6607987c354809cba818639dcd185147", "CFB", { { "iv",BinaryData("552c101a0b7c0ca143af258453937fa3",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "9b1a5a1369166e", "b7ab2a4cc71904");
    w(id(), "c028e6bf2b749ffa86759f2f84e93cb0", "CFB", { { "iv",BinaryData("288c752d9faccf367e5d0cca1fa6ec3b",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "324015878cdc82bf", "873250152fc6a5bb");
    w(id(), "d01da95d2c2a61da06ea78cfba59cc30", "CFB", { { "iv",BinaryData("f9a393ad90814faf262e3a5b1d97592e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "57c1a30e48166d9640", "e9a8c3b776edd39e3d");
    w(id(), "3a6f9159263fa6cef2a075caface5817", "CFB", { { "iv",BinaryData("0fc23662b7dbf73827f0c7de321ca36e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "87efeb8d559ed3367728", "8e9c50425614d540ce11");
    w(id(), "03edfe082550bd5ac8ddf64f42a0547f", "CFB", { { "iv",BinaryData("52acd8dab62c981da08e51939cc08dab",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "09", "21");
    w(id(), "38cf776750162edc63c3b5dbe311ab9f", "CFB", { { "iv",BinaryData("98fbbd288872c40f1926b16ecaec1561",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "eb24", "4878");
    w(id(), "c9053c87c3e56bc5e52bd31f6545f991", "CFB", { { "iv",BinaryData("b8f9640d0923da13fe6eb87b01f0cfa0",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "910949", "aeb6d2");
    w(id(), "e96771f5f20a89ee871261d2d18e1e46", "CFB", { { "iv",BinaryData("6e86403e33396655907ae06ef192262f",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "3b7f1f1c", "83cab2f3");
    w(id(), "92ad13ecb60bde1bb3b34ce07867672b", "CFB", { { "iv",BinaryData("f95a4060b8f80e3f839d4c3ca33dad94",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "17b9b9e16d", "49f73e652b");
    w(id(), "eb57b8dd076e7bbb33d4bfc4d7ecb27e", "CFB", { { "iv",BinaryData("51135997a067dcd2e016c57134c5fa52",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "ca989fa4e818", "b0eacbf2ca46");
    w(id(), "70abc48bb1be490183f0fe3df56195ff", "CFB", { { "iv",BinaryData("e251f179174b71ee1e488ab3dd200483",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "5405da1186b7e0", "08fbef9b2a369a");
    w(id(), "1273b8e0eee1a1ca827059b4d0a3a55d", "CFB", { { "iv",BinaryData("622cab49092d026f554dd98a6441dc26",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "d497df73afb9787c", "b3cb9d8892423aeb");
    w(id(), "49437e06b6faa5f20fd98bf71f8ff554", "CFB", { { "iv",BinaryData("63c818e0d3cb5b7054ef3e1e87df0e12",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "f203bcd402b65919da", "01992a986279c3685e");
    w(id(), "6399c1dc068ba3509845628fa9ed1a96", "CFB", { { "iv",BinaryData("1157c2766c86b754df485be9dd5851df",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(1) } }, "feff4e2e2458addf2a54", "c9c284e9abbfe6fb11fe");
    //CFB 16
    w(id(), "085b8af6788fa6bc1a0b47dcf50fbd35", "CFB", { { "iv",BinaryData("58cb2b12bb52c6f14b56da9210524864",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "4b5a872260293312eea1a570fd39c788", "e92c80e0cfb6d8b1c27fd58bc3708b16");
    w(id(), "701ccc4c0e36e512ce077f5af6ccb957", "CFB", { { "iv",BinaryData("5337ddeaf89a00dd4d58d860de968469",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "cc1172f2f80866d0768b25f70fcf6361aab7c627c8488f97525d7d88949beeea", "cdcf093bb7840df225683b58a479b00d5de5553a7e85eae4b70bf46dc729dd31");
    w(id(), "0a8e8876c96cddf3223069002002c99f", "CFB", { { "iv",BinaryData("b125a20ecd79e8b5ae91af738037acf7",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "4fd0ecac65bfd321c88ebca0daea35d2b061205d696aab08bea68320db65451a6d6c3679fdf633f37cf8ebcf1fa94b91", "cdd1ba252b2c009f34551a6a200602d71ffbf13e684a5e60478cdf74ffe61dfded344bdc7e8000c3b0b67552917f3e4c");
    w(id(), "b9ba9fa32cc491d8ac2beb5f99193d57", "CFB", { { "iv",BinaryData("95511452b71e53e93afad07ba1aa4d98",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "b40382705aaeea41097c309da6cd06010f15e09c0130fa4b3af69cc8da109d1f0f0a2661f1a8b89bab7e7009dcbb8a883d46254a830c45cd87981e0ea4e490fa", "800bf8840a73c9279a9cdb61436f8af20ae17c5a9b95bf25e456f48cc3cc2f9dffd86c48645fa187cac5becd058e46554ae3b4825a1ef4467849c9d13536adfc");
    w(id(), "5947bbd78b06bb5ea2fc67ed7b24216e", "CFB", { { "iv",BinaryData("8e4722ad2230b15f2eea302173bc1795",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "9e69423653c20c982794ed35d63c1a78e8ac14f37e1888ae4bf273bfe119891b2e4ed8ac46e7a9a463c7a710298d43b02f0c5606bcfc08adceeef2ec61867f8bede498e53163803f2f86fc58782fb841", "b23f0fdfc1519c408ee7a8ba46ea79f2cbea0032685af82f76a7e2b377741aaa618ef3953edbe39e8df1dd283b2e54a0f1327ce332188f6572574ce59428636f3b6e37054a4705b02bedf377e465e5f6");
    w(id(), "abce650e78f969b3b210151c74117fd2", "CFB", { { "iv",BinaryData("bc4659fbb7073c1f2185cd8ac5314bd1",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "322eae07df5ad2ddd64bba34e42d30c1b884f842e71efa123345a3fb0c39884c57dd4c2c6fb0c42e69ff5a269d59af3a6144853c182edb376ca65947d7ccefae6806ba25c4f527706ba85a353c0fd10e3cb244dd93a2d060d7b055058dde1dff", "40ec099d74b804fe5fc3810aaa6a1f66c5dd882711b1c95f9405e43cecfe14a48518f1077c97db0b3f69d4ed7a6d287f2b71b1cbfe62b851a343d92f50b94eaf16a6c39df972afa4c2e9cd3d171f62b3a2ca699c0219db8fb4aefc9aeafd488c");
    w(id(), "9f56e19b09dd3fee0e110f71e9967b7a", "CFB", { { "iv",BinaryData("1155cf4231bf7ac55d5e6eb27a974fad",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "ad1e4d3162a5084f581117639a13fc35df5449625ffe0f01e57d9a8726875be8515926ffe7449e30cd69ed4ca0c1b8b4486051c2d0fa2f6474a69c0afce2aec349d778a22edf81678145765b714c1b7c197287da56f59141d6978618729e1d89be20ace3de7d9b3c9b2d195ab6bc0fd4", "d9f0e125fe7f82b22d8f6084364388fba90809640bd6cb6331fe6eb2e4586b18af5f6b589aaeccd48e66392e1bdcc733e4f2ec3c7824a77323c757a147500d8aac31d7cee4be2d063db7f709bdb0abf63b184baa7ff3280e28fd378e4d2fa24688bf3bc4ab5d970c88728dfb2d4d61c2");
    w(id(), "31c485c996d6ceb2d17e0aa05b2490e4", "CFB", { { "iv",BinaryData("8c37f33405051b4c50abd16c6456643e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "ac68de6a2c2144c6b4fd975a8dec93447391e7c9a4fde63d36be7f23ad186f96cd92b5e8adb546880d100329e97fe8204fad860e6dd8b3c0eed4805387536b9ccc63d6c74938b83dce2c93cc0a04a6025b7563d9e5e7239ae27819fb3844848a51e4294f273401ad9e592f8a170334b042f0667233b29f92b9b13262eb73232a", "bcb37030075abbc91a75a302e5afe7281f7fd594c74a09737ae81f50573eb144c1d6c5190e10a61587848fefe2d3b0b3c05629f78a16758eaf40253322f3f7a8d755034be407b2af3761c3e704419686616194482cca5f603be89a1f06c7a190587c2f9338d48bcda1615c4257728ec34f2ce6ad0b58a197148ed10ede6a6561");
    w(id(), "556ccfa360ecb5025032dddb124cad4d", "CFB", { { "iv",BinaryData("d54c6fdcc85dc0a28c0b06205fee8854",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "71fbf180effac3dca0d69d40e4017dbe50455396f9fb6507ef7df26507de156cded8edd41a05fb25f352cbcdf3b2d770f90fa87f84863e0c2ed3b2dd770a1abfc489ad1ca82a28d061bd7039a6b5788da021657136def0c78d0b0cc7cfbec9512cf579811fd01185f3fdd2ab857328be4b63d293956b43df130e484b9861eccb1d06992b095e7febb0fb394c1954aeab", "e59b831cccd4acd94be7a9ffd3cc3167a9b6e085bfb976500d25fdfa2782f89c420241253f1b8ebdbbccd184d88a9db0da2ae1927137d1c2b08646ad50791ab66f7f88c365d567e8a8cbdf9aaae53d4e4ce964f9a14bd30a3c7cac53b245443dc16628d697afe62e0ed83bad707ad53f64a627b52bd66fb29484876919e41f8776e54cc9780841504f8c6b481cf112b2");
    w(id(), "7cb81fc4b203b0fa9bec49759bd515c2", "CFB", { { "iv",BinaryData("4d5e2fa3bf73f488b3e7e125f03dfbbe",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "362789b376d85eb8181d4eeea52d42e873ce7741c11a2f820383a7457b15489b09fb21ac4445959dc9e851b7d40682c50d7044bda46a5da39fae2bab73b3db9ed22edc7ec5da936dfa7451cb5f0a829ff0762738cc2686148f1e1f00dc3fe38139c9a173201fc1f052ca34736fc1ab3dc4e707f864d6119b7adb6c8ddd41c80de5d357d17e9c85ed7af1e4f72cb2656932ccce469202680109eef89a9f42f10a", "ac23259f68d4f82604cabd2e4237821c8b6c0aad0dfb1120b6b057223c994d62b5c6f63a25edbb797cd299f81ccb86d50134ad26107865142004c2d9d52fe3f91acf7b9b8111c8b4e14b05b173730e7b812036029846f1c1c6ffb30f6abcfc3e1ea631480e0d0bda106bb87319fdae09a11b89e8dde625d53a19c65ae58fbe3f4bcbc3c99af05cb0a7cc4b793d8cdb1cfa3173ede595c8c561f92c3fe3638b8d");
    w(id(), "beb622d0228cde29b342bbcf4c1c83b4", "CFB", { { "iv",BinaryData("75c282fa581d9c671edf5d540951b680",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "860476c81685b58e71e2599efe083ce5", "a5dd69d94112f3ffc2f267adde70b996");
    w(id(), "c4666081e0b0eddb10a9a607c807378f", "CFB", { { "iv",BinaryData("5f23623288e4a41b03186024755a10ea",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "2fd02dab9054248073ebc0b07aed383756ccfa4fa6298722775be6a9b4ed27a5", "7138c2b69191cf88702f7d25e9170dd6effdb80416b44f4d54e81fd7090f17e4");
    w(id(), "df010376a6b03279338773a70e012382", "CFB", { { "iv",BinaryData("67455decec549365742525d8dbf1fed9",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "9b9c3dea553ec235db0011b27191544171845b7bdda0dc04a089583959bba5ab7048f8ca87eab073a8b824fdd4e82e40", "c8bedc6e272366e4c584d2364fac4e2980359ace3a4ebc62d5bcf472b71ff2422477477058e61ad5d3b81cacf5a0bef6");
    w(id(), "ff01aa4f7106c6bd24399076f901a530", "CFB", { { "iv",BinaryData("089b4f6054eeeef76d4e13f75de64f7e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "ae9cb9dfa305af83e95a3b2099f70907edcd49fbc6efc5ebe744184c76b4f56bf35774f3fe215e1c8ee42172a2dd3e6f9ccd3d9bb044325e61a6bb97e48e9986", "228377c8fae0edfae8cc43e5a07ceefa5d8f1b84d33842e5649efe2396831ca4c524f1361561f153ab1e7ea21de9fec026dd30419fc6c0f2aa86196131b77aa0");
    w(id(), "d33d4062ab32298eafcca86b5088d5fd", "CFB", { { "iv",BinaryData("fcfffce8b020240f9f694adcb8ddf213",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "1fe1318adb99e6d4fced292902fe8c831ba488a43f85964d6ff54b322663b380bc99fed15568278cfe1d0af795c71355bf65e876855763655eec3abf3d4b27a0341d607f4bfbd82c8900fd436f7c4186", "208d49796fed810f37350b85d49c575f4d64ac973e02bde5157f7e3d811e3598283fd4f7998386a5813188bd21d93aedff377679dc592083e704fe893055ca2f5fa4863fa6ad10eef4f2f6616c5b8b6f");
    w(id(), "47e13544a7bbf74dd68ab5ce66e5bdaa", "CFB", { { "iv",BinaryData("69480b4dd38cf3b47e2b7652751395ae",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "3e2e583a3a0389ca324f2aaa52b7823904ab288dae562995cf1d70c796d785fd361261434eea480ceb3d369d969652c7ff194931c0a9bd978f5ae4094d6ef32d986a092c580ccbf865e5095a7b80559be13f842f9bea9e42a3a01ef8a24a6526", "26a7b649fd8435c5dd29ba1683ae0fb515ebb6e45cdfc4362d53f35128baf2f3a65cff33ecb3b80aa5152e118f943c8c742317a85cfa2501013b136783d522e25da8c1f398eb611d3ecb85a4125518957e960406cd01009f9a11a95a882fd586");
    w(id(), "ae86823695b48e8c612ae5a01b597f97", "CFB", { { "iv",BinaryData("b26eef7b1d14894c0c6388ce5273f4f2",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "569a910bc6aa97b8939ca703fc10ce0d171625bc735a1fea7148650541109d955b1b686c6cc404b2d3d92ad9faaff217dc7b31b038b770959aeccd1ca55d650364fde51df8d4f0aeb05fa364f5028f709c179ca6df0bdfc1cb850f238d755ac44a733fce558402be0c70bc0871b8e62f", "34a2642a230ad03d2c688cca80baeaee9a20e1d4c548b1cede29c6a45bf4df2c8c476f1a21a4431aed23661ce96342ef7cc60712f9de51c76a2205688ce67bfe1a8ae3104ef1e1b9a6347bfde498355d58be7aa9611a3e1632a6e291d2d8585266d187b3b3d7f143df05931677410c60");
    w(id(), "b85df29c9244229835d73441dc37555e", "CFB", { { "iv",BinaryData("c1375430efedb2d311a37bfa5ad2110e",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "c232a0bbf967ef28b74e7b809c62bc8c1cf2d52a273a84162900da834448fd567870471498f29770619dec504922e379eaba0d3a712602583d00279d8fc6a6d568cb94a330039a189ed5802abb7a2898c13ef89c00d73fca9a2f2ffc2107ab498212c56835c0fc26f835a69c00bb3eaa695ac20e8bdb0f5b5b6684d02bee8fb2", "2a0ea682b6b22122e828e2b6e1574303e7c1d32f1563a6c751dcf0077fd2d255f492740e2ef65485c28cde4995f43ca74f8a6f700d469ffd57e0af6f5137153b35f3e9e700693b0e6cc0aaaa1f5232932255464294bb1fdba056536bac40a96dd37a2c9496d37ec4ce0c6f61e539cecd466a802c128bce6b15890380f8b737f3");
    w(id(), "e96771f5f20a89ee871261d2d18e1e46", "CFB", { { "iv",BinaryData("8c664a37d245d26c0c55adfb424758ba",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "8aaafd56c5d5d54fbe16f115c3216bd1f4376666931a2ef1ffc5468ad12150c39250dca2d63c6ea166bb0ef4aaa3d5849c1f9c621c55826a1ca362f03bcba4dcbd654b300d16519710130e5360bd949aaded6a648f96dd8937a77287d4a4ac2941729475b635b9797476b4dca4171787ff15882d3b4872ed0999a7546dbb61698e8348f70e4a14981a78156150484532", "400c6d6bbfd0a676bcb88d20e41151abfed50e951e189e1d1ba2b30244de228e4ff382d39230f63576ad4728282f363b914d105689d1823f4761af631c5f80d4620d3b8eaff558fe4e8890c5ef0536b99d9cca2cf1d4cc72852ace9dacfacd8b60a3c1237ce773db2c908f7da159fa2c090b65a2bee723bbbd4437375b79b2bb33fd3c1a63cdf0d3f80e6ddba6f4299c");
    w(id(), "aef49da33f538ee66e178d4b6121055d", "CFB", { { "iv",BinaryData("842566e68b61ff7bf001f2642da62f64",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "415991f65e1a95040cef9960556f61e617827c30c74bf353cdd86173dbe4cc983a2ee6bc8ca6cfb71121e7b0d0178f2e13445c710dcc176b781201971171f7489f18faf110f39accd1cf08c85a958d7698b116f1c0d75812ac9b0b39aee7f7159ccad8fdae9b99f2d695eacf12c6469d5b51a34de26eac73613dcb2f77122cb1f8dd5162786a12052dc7b6dea6acc4989dcc7eafd9374f6c29697c74749ef16d", "6625811419bdee71535f597f7c228bafd890fd69b805a699ed58116a82bdb251abea7a4ef879a96fce8ee49518b9877a3a1e3cf346d3cd73738936d1cb6fff4b2353c8ca500a26689813ad2f67774e2343f3e4830259094d3b342e00faabeba5b8a893108a390c649836ddd5d12489b2dd591ca25361032e2da1207f793a1e69513002a90ccc036bb63e9c10be87df2def960cd7a1b1621e311735d7aee4419f");

    //CTR
    std::cout << "test set from " << R"<url>(https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf)<url>" << std::endl;
    w(id(), "2b7e151628aed2a6abf7158809cf4f3c", "CTR", { { "iv",BinaryData("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) } }, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");

    //GCM
    //std::cout << "test set from " << R"<url>(https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)<url>" << std::endl;
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(16) } }, "", "3247184b3c4f69a44dbcd22887bbb418");
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(16) } }, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4");
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(16) } }, "", "5f91d77123ef5eb9997913849b8dc1e9");
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(16) } }, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f598564c0232904af398a5b67c10b53a5024d");
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(16) } }, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091f07c2528eea2fca1211f905e1b6a881b");
    w(id(), "feffe9928665731c6d6a8f9467308308", "GCM", { { "iv",BinaryData("cafebabefacedbaddecaf888",BinaryData::Type::Hex) },{ "shift",static_cast<uint64_t>(16) },{ "aad",BinaryData("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",BinaryData::Type::Hex) },{ "tag_out",static_cast<uint64_t>(12) } }, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091f07c2528eea2fca1211f905e");

    print_error();
}