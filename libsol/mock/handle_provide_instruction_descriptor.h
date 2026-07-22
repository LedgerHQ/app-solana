#pragma once

#include "../instruction.h"
#include "sol/parser.h"

int validate_instruction_using_descriptor(const MessageHeader *header,
                                          const Instruction *instruction);

size_t get_descriptor_count(void);
bool instruction_descriptor_received(void);
