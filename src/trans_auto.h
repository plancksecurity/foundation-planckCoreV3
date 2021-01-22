// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef TRANS_AUTO_H
#define TRANS_AUTO_H

#include "transport.h"

PEP_STATUS auto_sendto(PEP_SESSION session, const message *msg);
PEP_STATUS auto_readnext(PEP_SESSION session, message **msg, PEP_transport_t **via);

#endif
