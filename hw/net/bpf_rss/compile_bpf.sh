

clang -O2 -emit-llvm -c tap_bpf_program.c -o - | llc -march=bpf -filetype=obj -o tap_bpf_program.o

