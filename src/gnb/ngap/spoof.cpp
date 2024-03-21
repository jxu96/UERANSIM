#include "task.hpp"
#include "nas/encode.hpp"
#include "nas/msg.hpp"
#include "nas/enums.hpp"
#include "ue/nas/enc.hpp"

#include <sys/ipc.h>
#include <sys/shm.h>

namespace nr::gnb
{

void NgapTask::retrieveIntKey() {
    using namespace std;

    key_t key = ftok("ueransim-shm", 65);
    int shmid = shmget(key, 1024, 0666 | IPC_CREAT);
    void * shmptr = shmat(shmid, (void*)0, 0);

    /* 4 bytes for length */
    uint32_t len = *((uint32_t*)shmptr);
    /* rest part for key value */
    m_intKey = OctetString::FromArray(((uint8_t*)shmptr)+4, len);

    m_logger->debug("IntKey: %s", m_intKey.toHexString().c_str());
    
    /* shut down after reading */
    shmdt(shmptr);
    shmctl(shmid, IPC_RMID, NULL);
}

void NgapTask::taskSpoof(const OctetString & nasPdu, OctetString & spoofMsg) {
    using namespace nas;

    auto msg = DecodeNasMessage(OctetView{nasPdu});
    if (msg != nullptr) {
        if (msg->epd == EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES) {
            auto sht = ((MmMessage &)(*msg)).sht;
            if (sht != ESecurityHeaderType::NOT_PROTECTED)
            {
                auto & target = (SecuredMmMessage &)(*msg);
                taskSecuredMmMessage(target);
                EncodeNasMessage(*msg, spoofMsg);
            }
            else {
                auto & target = (PlainMmMessage &)(*msg);
                taskPlainMmMessage(target);
                spoofMsg.append(nasPdu);
            }
        }
        else
        {
            // TODO SmMessage
        }
    }
}


void NgapTask::taskSecuredMmMessage(nas::SecuredMmMessage & msg) {
    using namespace nas;
    
    auto m = DecodeNasMessage(OctetView{msg.plainNasMessage});
    if (m != nullptr) {
        auto & target = (PlainMmMessage &)(*m);
        taskPlainMmMessage(target);
        msg.plainNasMessage = OctetString::Empty();
        EncodeNasMessage(*m, msg.plainNasMessage);
        // compute MAC code
        auto alg = ETypeOfIntegrityProtectionAlgorithm::IA2_128;
        auto cnt = nr::ue::NasCount{};
        auto is3gppAccess = true;
        auto isUplink = true;
        cnt.sqn = msg.sequenceNumber;
        auto mac = nr::ue::nas_enc::ComputeMac(alg, cnt, is3gppAccess, isUplink, m_intKey, msg.plainNasMessage);
        msg.messageAuthenticationCode = octet4{mac};
    }

}

void NgapTask::taskPlainMmMessage(nas::PlainMmMessage & msg) {
    using namespace nas;

    switch (msg.messageType)
    {
    case EMessageType::AUTHENTICATION_RESPONSE:
    {
        // auto & target = (AuthenticationResponse &)msg;
        m_logger->debug("UL NAS Transport: AUTHENTICATION_RESPONSE");
        break;
    }
    case EMessageType::SECURITY_MODE_COMPLETE:
    {
        retrieveIntKey();
        auto & target = (SecurityModeComplete &)msg;
        m_logger->debug("UL NAS Transport: SECURITY_MODE_COMPLETE");
        auto & imeiSv = (IE5gsMobileIdentity &) target.imeiSv;
        auto & nasMessageContainer = (IENasMessageContainer &) target.nasMessageContainer;
        auto m = DecodeNasMessage(OctetView{nasMessageContainer.data});
        if (m != nullptr) {
            taskPlainMmMessage((PlainMmMessage &)(*m));
        }
        nasMessageContainer.data = OctetString::Empty();
        EncodeNasMessage(*m, nasMessageContainer.data);
        break;
    }
    case EMessageType::REGISTRATION_COMPLETE:
    {
        m_logger->debug("UL NAS Transport: REGISTRATION_COMPLETE");
        break;
    }
    case EMessageType::UL_NAS_TRANSPORT:
    {
        auto &target = (UlNasTransport &)msg;
        m_logger->debug("UL NAS Transport: UL_NAS_TRANSPORT");
        if (target.sNssai.has_value()) {
            auto &nssai = target.sNssai.value(); 
            m_logger->debug("Captured NSSAI: sst-%b sd-%b", nssai.sst, nssai.sd);
            nssai.sd.reset();
        }
        break;
    }
    case EMessageType::REGISTRATION_REQUEST:
    {
        auto & target = (RegistrationRequest &)msg;
        m_logger->debug("UL NAS Transport: REGISTRATION_REQUEST");
        if(target.requestedNSSAI.has_value()) {
            auto &nssai = target.requestedNSSAI.value().sNssais.at(0);
            m_logger->debug("Sniffer: sst-%b sd-%b", nssai.sst, nssai.sd);
            nssai.sd.reset();
        }
    }
    
    default:
        break;
    }
}

void NgapTask::taskSecurityModeComplete(nas::SecurityModeComplete & msg) {
    using namespace nas;

    auto & imeiSv = (IE5gsMobileIdentity &) msg.imeiSv;
    auto & nasMessageContainer = (IENasMessageContainer &) msg.nasMessageContainer;
    m_logger->debug("%s", nasMessageContainer.data.toHexString().c_str());
    auto & plainMsg = (RegistrationRequest &)*(DecodeNasMessage(OctetView{nasMessageContainer.data}).get());

    // if (plainMsg.requestedNSSAI.has_value()) {
    //     auto & nssai = plainMsg.requestedNSSAI.value().sNssais.at(0);
    //     m_logger->debug("requested: sst-%b sd-%b", nssai.sst, nssai.sd);
    // }

    // if (msg->nasMessageContainer.has_value()) {
    //     auto ieMsg = DecodeNasMessage(OctetView{msg->nasMessageContainer.value().data});
    //     if (((MmMessage &)(*ieMsg)).sht != ESecurityHeaderType::NOT_PROTECTED) {
    //         m_logger->debug("secured");
    //         return;
    //     }
    //     if (((PlainMmMessage &)(*ieMsg)).messageType != EMessageType::REGISTRATION_REQUEST) {
    //         m_logger->debug("not reg req");
    //         return;
    //     }
    //     auto &regReq = (RegistrationRequest &)(*ieMsg);
    //     m_logger->debug("here");
    //     if (regReq.requestedNSSAI.has_value()) {
    //         auto &nssai = regReq.requestedNSSAI.value().sNssais.at(0);
    //         m_logger->debug("requested: sst-%b sd-%b", nssai.sst, nssai.sd);
    //         nssai.sd = octet3{0};

    //         msg->nasMessageContainer.value().data = OctetString::Empty();
    //         EncodeNasMessage(*ieMsg, msg->nasMessageContainer.value().data);
    //     }
    // }
}

} // namespace nr::gnb
