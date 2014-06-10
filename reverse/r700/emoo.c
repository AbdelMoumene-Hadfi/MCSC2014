/* qnix
 * XXX : password for this machine is h4h4h4hfunny
 * gcc -DNDEBUG -oemoo emoo.c -Os do stripping and those kind of things
 * to ship disable debugging with -DNDEBUG and remove all symbols and unnecessary
 * sections so it becomes a lil harder :>... also not that the comarpision algorithim
 * is vulnerable to a side-channel attack which is another solution to solve this challenge
 * possible solutions I can think of are :
 * 1. side channel attack by bruteforcing and counting instructions
 * executed if more then correct if less then try another character
 * and so on...
 * 2. by watching the memory of the virtual machine that is used for comparision and xoring
 * and will reveal alot with out understanding the way the machine works.. by the memory
 * of the machine I mean g_data.
 * 3. by understanding the way the machine work, disassembling the g_data opcodes into the 
 * virtual machine code and walking through the simple xoring algorithim.
 * XXX Note that you should change all opcodes so do some regex magic so it isn't
 * the same as qvm32 opcodes. So for example you want to change MOV opcode then
 * s/MOV_OPCODE/MOV_NEW_OPCODE/g and this should do it
 * ..etc
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define STACK_MAX 1024
#define END_VM    0xee
#define COPY_GD(x) x = (x << 8) | g_data[++regs[RI]]; \
                   x = (x << 8) | g_data[++regs[RI]]; \
                   x = (x << 8) | g_data[++regs[RI]]; \
                   x = (x << 8) | g_data[++regs[RI]];
// Debugging macros
#ifdef NDEBUG
#define SHOW_REG(x)
#define SHOW_FLAG
#define SHOW_REGS
#define SHOW_STACK(x)
#define DEBUG(M, ...)
#else
#define DEBUG(M, ...) printf(M, ##__VA_ARGS__)
#define SHOW_REG(x) if(x == R1) { printf("R1 "); } \
                          else if(x == R2) { printf("R2 "); } else if(x == R3) { printf("R3 "); } \
                          else if(x == R4) { printf("R4 "); } else if(x == RS) { printf("RS "); } \
                          else if(x == RI) { printf("RI "); } else { printf(" UNKOWN REGISTER "); }
#define SHOW_FLAG if(flags == FL) printf("FLAG LESS\n"); \
                            else if(flags == FG) printf("FLAG GREATER\n"); \
                            else if(flags == FE) printf("FLAG EQUAL\n");
#define SHOW_REGS printf("R1=%.8x\n", regs[R1]); \
                  printf("R2=%.8x\n", regs[R2]); \
                  printf("R3=%.8x\n", regs[R3]); \
                  printf("R4=%.8x\n", regs[R4]); \
                  printf("RS=%.8x\n", regs[RS]); \
                  printf("RI=%.8x\n", regs[RI]);
#define SHOW_STACK(x) { int i; for(i=0;i<x;i++) printf("stack[%d] = %.8x\n", i, stack[i]); }
#endif

int32_t *stack  = NULL;
int32_t regs[6] = { 0 };
int32_t flags   = 0;

enum OPCODES {
  RET   = 0x11,
  CALL  = 0x22,
  MOV   = 0x33,
  PUSH  = 0x44,
  ECALL = 0x55,
  CMP   = 0x66,
  JMP   = 0x77,
  JZ    = 0x88,
  JNZ   = 0x99,
  MOVP  = 0xaa,
  AND   = 0xbb,
  ADD   = 0xcc,
  XORP  = 0xdd
};

enum OPCODE_PARAM {
	REG = 0xAB,
	IMM = 0xBB
};

enum REGS {
	R1 = 0x00,
	R2 = 0x01,
	R3 = 0x02,
	R4 = 0x03,
	RS = 0x04,
	RI = 0x05
};

enum FLAGS {
	FU = 0xf0,
	FE = 0xf1,
	FG = 0xf2,
	FL = 0xf3
};

enum SYSCALLS {
  SYS_EXIT  = 0xe0,	// param exit_code=2
  SYS_WRITE = 0xe1,	// param fd=1size_t=1 value to write at r1
  SYS_READ  = 0xe2	// param fd=1,void*=2,size_t=3
};

/*
 * This is the application that will run under the virtual machine
 * it's a simple crackme that uses a key of the same length as the
 * correct password xors the input and compares it to hardcoded
 * values that should be the same. The comparision is weak since it
 * exists at the first unequal comparision which means there is a side-
 * channel attack on this simple algorithim to fix the problem which will
 * make the level a little harder the algorithim needs to compare n no matter
 * what the input result is and sets the data into a flag or a counter that is
 * checked at the end.
 * */
uint8_t g_data[5000] =
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    // Get password
    "\x55\xe1\x01\x00\x00\x03\x0d\x0c" // write(0x01, "ENTER PASS :"@0x030d?, 0x0c);
    "\x55\xe2\x00\x00\x00\x00\xf2\x0c" // read(0x00, 0x000000f2, 0x0c);
    // XOR input with our xor key 
    "\x33\xbb\x00\x00\x00\x00\xf2" // MOV [IMM] r1 0x000000f2
    "\xdd\xbb\x00\x30"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\xcd"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x44"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x29"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\xff"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x93"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x6f"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x10"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x0d"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x9e"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\xa5"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001
    "\xdd\xbb\x00\x80"             // XOR [IMM] r1 0x..
    "\xcc\xbb\x00\x00\x00\x00\x01" // ADD [IMM] r1 0x00000001

    // Do Comparisions
    "\xaa\xbb\x00\x00\x00\x00\xf2" // MOVP r1, 0x000000f2
    "\x33\xbb\x01\x00\x00\x00\x58" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xf3" // MOVP r3, 0x000000f3
    "\x33\xbb\x03\x00\x00\x00\xf9" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\xaa\xbb\x00\x00\x00\x00\xf4" // MOVP r1, 0x000000f4
    "\x33\xbb\x01\x00\x00\x00\x2c" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xf5" // MOVP r3, 0x000000f5
    "\x33\xbb\x03\x00\x00\x00\x1d" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\xaa\xbb\x00\x00\x00\x00\xf6" // MOVP r1, 0x000000f6
    "\x33\xbb\x01\x00\x00\x00\x97" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xf7" // MOVP r3, 0x000000f7
    "\x33\xbb\x03\x00\x00\x00\xa7" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\xaa\xbb\x00\x00\x00\x00\xf8" // MOVP r1, 0x000000f8
    "\x33\xbb\x01\x00\x00\x00\x07" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xf9" // MOVP r3, 0x000000f9
    "\x33\xbb\x03\x00\x00\x00\x76" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\xaa\xbb\x00\x00\x00\x00\xfa" // MOVP r1, 0x000000fa
    "\x33\xbb\x01\x00\x00\x00\x78" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xfb" // MOVP r3, 0x000000fb
    "\x33\xbb\x03\x00\x00\x00\xf0" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\xaa\xbb\x00\x00\x00\x00\xfc" // MOVP r1, 0x000000fc
    "\x33\xbb\x01\x00\x00\x00\xcb" // MOV r2, 0x000000..
    "\xaa\xbb\x02\x00\x00\x00\xfd" // MOVP r3, 0x000000fd
    "\x33\xbb\x03\x00\x00\x00\xf9" // MOV r4, 0x000000..
    "\x66\xab\x00\x01"             // CMP r1, r2
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    "\x66\xab\x02\x03"             // CMP r3, r4
    "\x99\xbb\x00\x00\x02\xf9"     // JNZ failed
    // Win if not failed
    "\x55\xe1\x01\x00\x00\x03\x09\x04" // write(0x01, "WIN\n", 0x4)
    "\x55\xe0\xff"                     // EXIT(ff);
    // FAILED_INPUT
    "\x55\xe1\x01\x00\x00\x03\x02\x07" // write(0x01, "FAILED\n", 0x0c);
    "FAILED\n"
    "WIN\n"
    "ENTER PASS : "
    "\xee"
    ;

int main(int argc, char **argv)
{

	printf("emoo VM layer challenge by Simo36 & Qnix (MCSC 2014) \n");
	stack = (int32_t *) malloc(sizeof(int32_t) * STACK_MAX);
	if (!stack) return -1;
	SHOW_REGS;

	while (g_data[regs[RI]] != END_VM) {
		switch (g_data[regs[RI]]) {
		case RET:
			break;
		case CALL:
			break;
		case MOV:
			{
				DEBUG("[%.8x] MOV ", regs[RI]);
				uint8_t mov_type = g_data[++regs[RI]];
				if (mov_type == REG) {
					DEBUG(" [REG] ");
					uint8_t dst = g_data[++regs[RI]];
					uint8_t src = g_data[++regs[RI]];
					regs[dst] = regs[src];
					SHOW_REG(dst);
					SHOW_REG(src);
					DEBUG("\n");
				} else if (mov_type == IMM) {
					DEBUG(" [IMM] ");
					uint8_t dst = g_data[++regs[RI]];
					SHOW_REG(dst);
					regs[dst] = 0;
					COPY_GD(regs[dst]);
					DEBUG("%.8x\n", regs[dst]);
				} else {
					DEBUG(" [!REG&!IMM]\n");
				}
			}
			break;
		case PUSH:
			{
				DEBUG("[%.8x] PUSH ", regs[RI]);
				uint8_t push_type = g_data[++regs[RI]];
				if (push_type == REG) {
					uint8_t r = g_data[++regs[RI]];
					stack[regs[RS]++] = regs[r];
					SHOW_REG(r);
					DEBUG("\n");
				} else if (push_type == IMM) {
					int data = 0;
					COPY_GD(data);
					stack[regs[RS]++] = data;
					DEBUG("%.8x\n", data);
				} else {
					DEBUG(" [!REG&!IMM]\n");
				}
			}
			break;
		case ECALL:
			{
				DEBUG("[%.8x] ECALL ", regs[RI]);
				uint8_t syscall_n = g_data[++regs[RI]];
				switch (syscall_n) {
				case SYS_EXIT:
					{
						uint8_t exit_code =
						    g_data[++regs[RI]];
						DEBUG("exit(%x)\n", exit_code);
						exit(exit_code);
					}
					break;
				case SYS_WRITE:
					{
						uint8_t fd = g_data[++regs[RI]];
						int buffer_address = 0;
						COPY_GD(buffer_address);
						uint8_t sz = g_data[++regs[RI]];
						DEBUG("write(%x, %.8x, %x)\n",
						      fd, buffer_address, sz);
						write(fd,
						      &g_data[buffer_address],
						      sz);
					}
					break;
				case SYS_READ:
					{
						uint8_t fd = g_data[++regs[RI]];
						int buffer_address = 0;
						COPY_GD(buffer_address);
						uint8_t sz = g_data[++regs[RI]];
						int ret =
						    read(fd,
							 &g_data
							 [buffer_address], sz);
						DEBUG
						    ("read(%x, %.8x, %x) -> read %d bytes\n",
						     fd,
						     &g_data[buffer_address],
						     sz, ret);
					}
					break;
				default:
					DEBUG(" unkown syscall %x\n",
					      syscall_n);
					break;
				}
			}
			break;
		case CMP:
			{
				DEBUG("[%.8x] CMP ", regs[RI]);
				uint8_t cmp_type = g_data[++regs[RI]];
				if (cmp_type == REG) {
					uint8_t dst = g_data[++regs[RI]];
					uint8_t src = g_data[++regs[RI]];
					SHOW_REG(dst);
					SHOW_REG(src);
					DEBUG("\n");
					if (regs[dst] == regs[src])
						flags = FE;
					else if (regs[dst] < regs[src])
						flags = FL;
					else if (regs[dst] > regs[src])
						flags = FG;
				} else if (cmp_type == IMM) {
					int dst = 0;
					int src = 0;
					COPY_GD(dst);
					COPY_GD(src);
					DEBUG("%.8x %.8x\n", dst, src);
					if (dst == src)
						flags = FE;
					else if (dst < src)
						flags = FL;
					else if (dst > src)
						flags = FG;
				} else {
					DEBUG(" [!REG&!IMM]\n");
				}
				SHOW_FLAG;
			}
			break;
		case JMP:
			{
				DEBUG("[%.8x] JMP ", regs[RI]);
				uint8_t jmp_type = g_data[++regs[RI]];
				if (jmp_type == IMM) {
					DEBUG(" [IMM] ");
					int v = 0;
					COPY_GD(v);
					regs[RI] = v;
					DEBUG(" -> %.8x\n", v);
				} else {
					DEBUG(" [!IMM]\n");
				}
			}
			break;
		case JZ:
			DEBUG("[%.8x] JZ ", regs[RI]);
			SHOW_FLAG;
			uint8_t jz_type = g_data[++regs[RI]];
			if (jz_type == IMM) {
				DEBUG(" [IMM] ");
				if (flags == FE) {
					int v = 0;
					COPY_GD(v);
					regs[RI] = v;
					DEBUG(" -> %.8x\n", v);
				} else {
					DEBUG(" condition not met\n");
          // get rid of the next 4 bytes
          // assuming there are 4 bytes
					regs[RI]++;
					regs[RI]++;
					regs[RI]++;
					regs[RI]++;
				}
			} else {
				DEBUG(" ![IMM]\n");
			}
			break;
		case JNZ:
			DEBUG("[%.8x] JNZ ", regs[RI]);
			SHOW_FLAG;
			uint8_t jnz_type = g_data[++regs[RI]];
			if (jnz_type == IMM) {
				if (flags != FE) {
					int v = 0;
					COPY_GD(v);
					regs[RI] = v;
					DEBUG(" -> %.8x\n", v);
				} else {
					DEBUG(" condition not met\n");
          // get rid of the next 4 bytes
          // assuming there are 4 bytes
					regs[RI]++;
					regs[RI]++;
					regs[RI]++;
					regs[RI]++;
				}
			} else {
				DEBUG(" ![IMM]\n");
			}
			break;
		case MOVP:
			{
				DEBUG("[%.8x] MOVP ", regs[RI]);
				uint8_t movp_type = g_data[++regs[RI]];
				if (movp_type == IMM) {
					DEBUG(" [IMM] ");
					uint8_t dst = g_data[++regs[RI]];
					int idx = 0;
					COPY_GD(idx);
					regs[dst] = g_data[idx];
					SHOW_REG(dst);
					DEBUG(" %.8x\n", idx);
					SHOW_REGS;
				} else {
					DEBUG(" [!IMM]\n");
				}
			}
			break;
		case AND:
			DEBUG("[%.8x] AND ", regs[RI]);
			uint8_t and_type = g_data[++regs[RI]];
			if (and_type == REG) {
				DEBUG(" [REG] ");
				uint8_t dst = g_data[++regs[RI]];
				uint8_t src = g_data[++regs[RI]];
				regs[dst] &= regs[src];
				SHOW_REG(dst);
				SHOW_REG(src);
				DEBUG("\n");
			} else if (and_type == IMM) {
				DEBUG(" [IMM] ");
				uint8_t dst = g_data[++regs[RI]];
				int val = 0;
				COPY_GD(val);
				regs[dst] &= val;
				SHOW_REG(dst);
				DEBUG(" %.8x\n", val);
			} else {
				DEBUG(" [!reg|!imm]\n");
			}
			break;
		case ADD:
			DEBUG("[%.8x] ADD ", regs[RI]);
			uint8_t add_type = g_data[++regs[RI]];
			if (add_type == REG) {
				uint8_t dst = g_data[++regs[RI]];
				uint8_t src = g_data[++regs[RI]];
				regs[dst] += regs[src];
				SHOW_REG(dst);
				SHOW_REG(src);
				DEBUG("\n");
			} else if (add_type == IMM) {
				uint8_t dst = g_data[++regs[RI]];
				int val = 0;
				COPY_GD(val);
				regs[dst] += val;
				SHOW_REG(dst);
				DEBUG(" %.8x\n", val);
			} else {
				DEBUG(" [!reg|!imm]\n");
			}
			break;
		case XORP:
			{
				DEBUG("[%.8x] XORP ", regs[RI]);
				uint8_t xor_type = g_data[++regs[RI]];
				if (xor_type == REG) {
					DEBUG(" [REG] ");
					uint8_t dst = g_data[++regs[RI]];
					uint8_t src = g_data[++regs[RI]];
					g_data[regs[dst]] ^= regs[src];
					SHOW_REG(dst);
					SHOW_REG(src);
					DEBUG("\n");
				} else if (xor_type == IMM) {
					DEBUG(" [IMM] ");
					uint8_t dst = g_data[++regs[RI]];
					uint8_t val = g_data[++regs[RI]];
					SHOW_REG(dst);
					DEBUG(" %x\n", val);
					g_data[regs[dst]] ^= val;
				} else {
					DEBUG(" [!reg|!imm]\n");
				}

			}
			break;
		default:
			DEBUG("[%.8x] Unkown opcode %x\n", regs[RI],
			      g_data[regs[RI]]);
			break;
		}
		regs[RI]++;
	}

	SHOW_STACK(12);
	SHOW_REGS;

	free(stack);
	return 0;
}
