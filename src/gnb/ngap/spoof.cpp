#include "task.hpp"
#include "nas/encode.hpp"
#include "nas/msg.hpp"
#include "nas/enums.hpp"

namespace nr::gnb
{

const OctetString& NgapTask::makeSpoof(const OctetString &nasPdu)
{
    MITMDecode(nasPdu);
    return nasPdu;
}

void NgapTask::MITMDecode(const OctetString &nasPdu) {
    using namespace nas;

    auto msg = DecodeNasMessage(OctetView{nasPdu});
    if (msg != nullptr) {
        if (msg->epd == EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES) {
            auto &mmMsg = (MmMessage &)*msg;
            PlainMmMessage *mmPlainMsg = nullptr;
            if (mmMsg.sht == ESecurityHeaderType::NOT_PROTECTED)
            {
                mmPlainMsg = &static_cast<PlainMmMessage &>(mmMsg);
            }
            else
            {
                auto &mmSecuredMsg = static_cast<SecuredMmMessage &>(mmMsg);
                mmPlainMsg = &(PlainMmMessage &)*DecodeNasMessage(OctetView{mmSecuredMsg.plainNasMessage});
            }
            switch (mmPlainMsg->messageType)
            {
            case EMessageType::AUTHENTICATION_RESPONSE:
            {
                m_logger->debug("UL NAS Transport: AUTHENTICATION_RESPONSE");
                break;
            }
            case EMessageType::SECURITY_MODE_COMPLETE:
            {
                m_logger->debug("UL NAS Transport: SECURITY_MODE_COMPLETE");
                auto &msgContainer = (IENasMessageContainer &)((SecurityModeComplete *)mmPlainMsg)->nasMessageContainer;
                m_logger->debug("NAS Message Container: %s", msgContainer.data.data)
                break;
            }
            case EMessageType::REGISTRATION_COMPLETE:
            {
                m_logger->debug("UL NAS Transport: REGISTRATION_COMPLETE");
                break;
            }
            case EMessageType::UL_NAS_TRANSPORT:
            {
                m_logger->debug("UL NAS Transport: UL_NAS_TRANSPORT");
                auto &nssai = (IESNssai &)((UlNasTransport *)mmPlainMsg)->sNssai;
                m_logger->debug("NSSAI - sst: %b sd: %b", nssai.sst, nssai.sd);
                break;
            }
            }
        }
        else
        {
            auto &smMsg = static_cast<SmMessage &>(*msg);
            m_logger->debug("UL NAS SM Message. Type: %b", smMsg.messageType);
        }
    }
    
}

} // namespace nr::gnb
