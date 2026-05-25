#include "handle_provide_instruction_substructure.h"
#include "io.h"
#include "apdu.h"
#include "globals.h"

int handle_provide_instruction_substructure(void) {
    PRINTF("handle_provide_instruction_substructure stub\n");
    return io_send_sw(ApduReplyUnimplementedInstruction);
}
