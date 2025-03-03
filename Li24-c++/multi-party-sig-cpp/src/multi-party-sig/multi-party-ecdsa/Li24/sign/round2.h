
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_ROUND4_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_ROUND4_H

#include <string>
#include <vector>
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/message.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

class Round2 : public safeheron::mpc_flow::mpc_parallel_v2::MPCRound {
public:
    std::vector<Round1BCMessage> bc_message_arr_;

public:
    Round2(): MPCRound(safeheron::mpc_flow::mpc_parallel_v2::MessageType::BROADCAST,
                       safeheron::mpc_flow::mpc_parallel_v2::MessageType::None){}

    void Init() override;

    bool ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) override;

    bool ReceiveVerify(const std::string &party_id) override;

    bool ComputeVerify() override;

    bool MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                     std::vector<std::string> &out_des_arr) const override;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_ROUND4_H
