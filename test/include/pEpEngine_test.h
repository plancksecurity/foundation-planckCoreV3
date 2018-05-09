#include <iomanip>

#define ASSERT_STATUS(status) { cout << setfill('0') << "status: 0x" << hex << setw(4) << status << "\n"; assert(status == PEP_STATUS_OK); cout << std::dec }
