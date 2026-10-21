CC ?= clang
TARGET = sovereign_core.elf

CFLAGS = -target aarch64-none-elf -march=armv8-a+nofp+nosimd \
         -ffreestanding -nostdlib -mgeneral-regs-only -O2 -Wall \
         -Iinclude -Isrc

LDFLAGS = -target aarch64-none-elf -nostdlib -Wl,-T,linker.ld -Wl,--gc-sections

SRCS = arch/aarch64/entry.S src/sovereign_core.c
OBJS = arch/aarch64/entry.o src/sovereign_core.o

all: $(TARGET)

arch/aarch64/entry.o: arch/aarch64/entry.S
	$(CC) $(CFLAGS) -c $< -o $@

src/sovereign_core.o: src/sovereign_core.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

verify: $(TARGET)
	@echo "=== UNRESOLVED SYMBOLS ==="
	@nm -u $(TARGET) || true
	@echo "=== INSTRUCTION VECTOR/FP AUDIT ==="
	@llvm-objdump -d $(TARGET) | grep -E '(fadd|fsub|fmul|fdiv|fmov|ldr [qds]|str [qds]|fcvt)' || echo "ZERO FP/SIMD INSTRUCTIONS DETECTED"
	@echo "=== SECTION MAPPINGS ==="
	@llvm-readelf -S $(TARGET)

clean:
	rm -f arch/aarch64/*.o src/*.o $(TARGET)

.PHONY: all clean verify
