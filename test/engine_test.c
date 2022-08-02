#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <capstone/capstone.h>

#define CODE "\x37\x25\x01\x00" // Little endian opcode

int main(void) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &handle) != CS_ERR_OK)
    return -1;
  count =
      cs_disasm(handle, (uint8_t *)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
             insn[j].op_str);
    }

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);

  return 0;
}
