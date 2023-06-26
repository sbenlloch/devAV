import lz4.frame
import json
import glob
import sys
import os

if len(sys.argv) < 1:
    print(f"Usage: {sys.argv[0]} <dataset_folder>")
    sys.exit(0)

def load_compressed_json(file_path):
    """
    Loads a compressed JSON file using the LZ4 compression algorithm.

    :param file_path: The path to the compressed JSON file.
    :return: The contents of the JSON file as a dictionary.
    """
    try:

        with lz4.frame.open(file_path, 'rb') as f:
            compressed_data = f.read()
            data = json.loads(lz4.frame.decompress(compressed_data))
            return data

    except:

        with open(file_path, 'rb') as f:
            compressed_data = f.read()

        decompressed_data = lz4.frame.decompress(compressed_data)
        data = json.loads(decompressed_data.decode('utf-8', errors='replace'))
        return data


Memory = {"movabs", "push", "mov", "movzx", "pop", "cmove", "movsd", "cmpxchg", "cmps", "lods", "stos", "scas", "xchg", "lodsd", "stosd", "scasd", "xlatb", "scasb", "movsb", "movdqa", "movups", "movaps", "cmovns", "cmovbe", "cmovle", "cmova", "cmovae" "cmovg", "cmovge", "cmovb", "cmovl", "cmovo", "rep stosd", "rep movsd", "stosb", "lodsb", "rep stosb", "rep movsb", "movdqu", "popal", "pushal", "cmovne", "cmovs", "bswap", "cmovae", "storw", "mvn", "movq", "movsw", "movd", "ldr", "str", "ldrb", "strb", "ldm", "stp"}
FloatingPoint = {"fnstenv", "fcom", "fistp", "fisub", "fiadd", "fidiv", "ficom", "fimul", "fsubr", "f2xm1", "fidivr", "fdiv", "fild", "fnstcw", "fnstsw", "lahf", "fistp", "sets", "fstp", "fld", "fadd", "fcomp", "fdivr", "fmul", "fst", "fldcw", "fsub", "fxch", "fisttp", "cmpsd", "fmul", "fst", "fldcw", "fsub", "fxch", "fisttp", "cmpsd"}
ConditionalJump = {"jno", "js", "jae", "je", "jb", "jne", "jns", "ja", "jbe", "jle", "jg", "jge", "jl", "jle", "jo", "jp", "jpe", "jpo", "sete", "seta", "setne", "jnp", "bne", "beq", "loop", "loope", "loopne", "repne scasb", "jecxz", "setge", "daa", "aas", "ble", "bgt", "setl", "blo", "cmn", "bhs", "asrs", "asr"}
Arithmetic = {"sub", "add", "nop", "shl", "sar", "div", "imul", "dec", "mul", "inc", "neg", "not", "adc", "sbb", "rol", "ror", "shr", "sal", "idiv", "rcr", "rcl", "aaa", "das", "aad", "shrd", "shld", "adds", "subs", "rsb"}
System = {"in", "out", "cli", "sti", "hlt", "nop", "wait", "cmc", "cld", "std", "sahf", "pushfd", "clc", "cpuid", "syscall", "stc", "salc"}
TypeConversion = {"cdq", "cbw", "cwde", "cwtl", "cwd", "movsx", "movsxd", "movzx", "aam", "cdqe"}
AtomicOperations = {"lock cmpxchg", "lock sbb", "lock xadd", "lock dec", "lock inc", "lock add", "lock or"}
UnconditionalJump = {"jmp", "call", "ret", "iretd", "retf", "jrcxz", "xbegin", "b", "bl", "bsr", "ljmp"}
Privileged = {"int", "endbr64", "bnd jmp", "bnd ret", "int3", "endbr32"}
Crypto = {"aesenc", "aesdec", "aesimc", "aeskeygenassist"}
Logic = {"xor", "test", "and", "or", "bt", "bts", "xorps"}
Addressing = {"lea", "leave", "enter"}
Comparison = {"cmp", "setg", "setb"}


def group(inst_freq, num_inst) -> dict:
    groups = {
        "Arithmetic": 0,
        "Memory": 0,
        "ConditionalJump": 0,
        "UnconditionalJump": 0,
        "Logic": 0,
        "System": 0,
        "Privileged": 0,
        "Crypto": 0,
        "Comparison": 0,
        "Addressing": 0,
        "TypeConversion": 0,
        "AtomicOperations": 0,
        "FloatingPoint": 0,
        "Undefined": 0
    }

    for (inst, freq) in inst_freq.items():

        if inst in Arithmetic:
            groups["Arithmetic"] += freq
        elif inst in Memory:
            groups["Memory"] += freq
        elif inst in ConditionalJump:
            groups["ConditionalJump"] += freq
        elif inst in UnconditionalJump:
            groups["UnconditionalJump"] += freq
        elif inst in Logic:
            groups["Logic"] += freq
        elif inst in System:
            groups["System"] += freq
        elif inst in Privileged:
            groups["Privileged"] += freq
        elif inst in Crypto:
            groups["Crypto"] += freq
        elif inst in Comparison:
            groups["Comparison"] += freq
        elif inst in Addressing:
            groups["Addressing"] += freq
        elif inst in TypeConversion:
            groups["TypeConversion"] += freq
        elif inst in AtomicOperations:
            groups["AtomicOperations"] += freq
        elif inst in FloatingPoint:
            groups["FloatingPoint"] += freq
        else:
            groups["Undefined"] += freq

    return groups


dataset = os.path.abspath(sys.argv[1])

for featurefile in glob.glob('**/features.json', recursive=True, root_dir=dataset):
    output_file = f"{dataset}/{os.path.dirname(featurefile)}/groups.feature"
    insts_number = 0
    groups = {}
    try:
        j = load_compressed_json(featurefile)
        insts_freq = j["CODE"]["INSTS_STATS"]["inst_type_freq"]
        insts_number = j["CODE"]["INSTS_STATS"]["num_insts"]
        groups = group(insts_freq, insts_number)

    except:
        pass

    with open(output_file, 'w') as outfile:
        json.dump(groups, outfile)
    print(output_file)
