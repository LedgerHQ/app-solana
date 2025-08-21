#include "handle_provide_instruction_descriptor.h"

int validate_instruction_using_descriptor(const MessageHeader *header,
                                          const Instruction *instruction) {
    UNUSED(header);
    UNUSED(instruction);
    return 0;
}

uint8_t get_descriptor_count(void) {
    return 0;
}
