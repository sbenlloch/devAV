from multiprocessing import Process, Manager
from inspect import getsourcefile
from os.path import abspath, dirname
import traceback
import hashlib
import pickle
import json
import sys
import os

from IPython.core.interactiveshell import IPython

from .log import log
from BinSniff import binsniff

from transformers import BertTokenizer
from tqdm import tqdm
import numpy as np
import lightgbm

import warnings
warnings.filterwarnings('ignore')

### Globals ###

tool_path = os.path.dirname(os.path.abspath(__file__))
mnemonics_pkl = f"{tool_path}/models/LGBM_mnemonics.pkl"
functions_pkl = f"{tool_path}/models/LGBM_functions.pkl"
strings_pkl = f"{tool_path}/models/LGBM_strings.pkl"
entropy_pkl = f"{tool_path}/models/LGBM_entropy.pkl"
generic_pkl = f"{tool_path}/models/LGBM_generic.pkl"

sections_file = f"{tool_path}/data/top-sections.json"
all_sections = None

functions_file = f"{tool_path}/data/top-functions.json"
all_functions = None

# Create BERT instance
tokenizer = BertTokenizer.from_pretrained("bert-large-uncased")

###############

def check_model():
    """
    Verifies if the model exists in the specified directory.

    If the model is not found in the directory, logs the necessary steps to
    resolve the issue, and terminates the program. If the model exists,
    it logs a success message.

    Raises:
        SystemExit: If the models do not exist in the project directory.
    """
    if not os.path.exists(f"{mnemonics_pkl}"):
        log("e", "It is necessary to unpack the models in the project folder.")
        log("e", f"Project in: {tool_path}")
        log("e", "More details in the Readme.md")
        sys.exit(1)

    log("i", "Checked models")


vault_models = {}
def load_model(modelpath):
    """
    Loads a machine learning model from a given path.

    If the model has been loaded before, it fetches from an in-memory
    dictionary to avoid re-reading the model file. If it is not in memory,
    it loads the model from the file and stores it in memory for future use.

    Args:
        modelpath (str): The path to the model file.

    Returns:
        The loaded model.

    Raises:
        FileNotFoundError: If the model file does not exist.
    """
    if modelpath in vault_models:
        return vault_models[modelpath]

    with open(modelpath, "rb") as m:
        model = pickle.load(m)

    vault_models[modelpath] = model

    return model

### Utilities for feature extraction ###

def init_sections():
    """
    Initialize and retrieve the dictionary of all sections.

    Returns:
        dict: Dictionary containing all sections.

    """
    global all_sections
    if all_sections is not None:
        return all_sections

    with open(sections_file, "r") as f:
        all_sections = json.load(f)

    return all_sections

def init_functions():
    """
    Initialize and retrieve the dictionary of all functions.

    Returns:
        dict: Dictionary containing all functions.

    """
    global all_functions
    if all_functions is not None:
        return all_functions

    with open(functions_file, "r") as f:
        all_functions = json.load(f)

    return all_functions

def list_to_numpy_array(lst):
    """
    Convert a list to a numpy array of float dtype.

    Args:
        lst (list): List of values to be converted.

    Returns:
        numpy.ndarray: Numpy array of float dtype.

    """
    return np.array(lst, dtype=float)

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

### Feature extraction ###

def entropy_feat(jsonfile):
    """
    Convert jsonfile to entropies features suitable for ML models.

    Args:
        jsonfile (dict): JSON file containing entropy data.

    Returns:
        numpy.ndarray: Numpy array of entropy features.

    """
    sections = init_sections()
    assert isinstance(sections, dict)
    current_sections = sections.copy()
    current_sections["NOT_DEFINED"] = 0
    general_entropy = 0

    try:
        general_entropy = jsonfile["ENTROPY"] / 8

        if "STATIC" in jsonfile:
            entropies = jsonfile["STATIC"]["ENTROPIES"]
            for section, entropy in entropies.items():
                section = section.encode('ascii', 'ignore').decode()
                section = section.replace('\n', ' ').replace('\r', '')
                if "." in section:
                    section = ".".join(section.split(".")[:2])

                if section in sections:
                    current_sections[section] = entropy / 8
                else:
                    if "NOT_DEFINED" in current_sections:
                        if current_sections["NOT_DEFINED"] < (entropy / 8):
                            current_sections["NOT_DEFINED"] = entropy / 8
                    else:
                        current_sections["NOT_DEFINED"] = entropy / 8
    except:
        pass

    current_sections["GENERAL"] = general_entropy

    return list_to_numpy_array(list(current_sections.values()))

def functions_feat(jsontext):
    """
    Perform feature extraction for functions based on the provided jsontext.

    Args:
        jsontext (str): JSON text for feature extraction.

    Returns:
        numpy.ndarray: Numpy array of feature values.

    """
    functions = init_functions()
    assert isinstance(functions, dict)
    current_functions = functions.copy()
    current_functions["NOT_DEFINED"] = 0
    current_functions["NUMBER"] = 0

    try:
        # Get functions
        functions_set = set()
        magic = jsontext["MAGIC"]
        if 'ELF' in magic:
            symbol_table_sections = jsontext["STATIC"]["SYMBOL_TABLE_SECTIONS"]
            for section in symbol_table_sections:
                symbols = section["SYMBOLS"]
                for symbol in symbols:
                    if symbol["TYPE"] == "FUNC":
                        functions_set.add(symbol["NAME"])

        elif "STATIC" in jsontext:
            import_table = jsontext["STATIC"]["IMPORT_TABLE"]
            for table in import_table:
                imports = table["imports"]
                for name in imports:
                    functions_set.add(name)

        for function in functions_set:
            if function in functions:
                current_functions[function] = 1
            else:
                current_functions["NOT_DEFINED"] += 1

            current_functions["NUMBER"] += 1

    except:
        pass

    return list_to_numpy_array(list(current_functions.values()))

def strings_feat(jsontext):
    """
    Extracts features from a JSON object containing string data.

    Args:
        jsontext (dict): A JSON object containing the required string data.

    Returns:
        numpy.ndarray: An array containing the extracted features.

    Raises:
        None.

    """

    size = 256

    try:
        str_list = sorted(jsontext["COMMON"]["STRINGS"], key=len, reverse=True)
        join_str = " ".join(str_list)
    except:
        join_str = " "

    inputs = tokenizer(
        join_str,
        truncation=True,
        padding='max_length',
        return_tensors='pt',
    )

    input_tensor = inputs['input_ids'].float()
    input_tensor = input_tensor / tokenizer.vocab_size

    sized_input_tensor = input_tensor[:,:size]
    input_list = sized_input_tensor.tolist()[0]

    return list_to_numpy_array(input_list)

def mnemonics_feat(jsontext):
    """
    Extracts instruction statistics from JSON data and returns them as a numpy array.

    Args:
        jsontext (dict): JSON data

    Returns:
        numpy.array: Grouped instruction statistics. If the data is missing or incorrect,
                     returns an empty numpy array.
    """
    insts_number = 0
    groups = {}
    try:
        insts_freq = jsontext["CODE"]["INSTS_STATS"]["inst_type_freq"]
        insts_number = jsontext["CODE"]["INSTS_STATS"]["num_insts"]
        groups = group(insts_freq, insts_number)
    except:
        pass

    return list_to_numpy_array(list(groups.values()))

### Utilities and globals for generic features ###

def hash_md5_dict(dic):
    string = str(sorted(dic.items()))

    md5_hash = hashlib.md5(string.encode()).hexdigest()
    value = int(md5_hash, 16) / (2 ** 128)  # Size of MD5 in bits is 128

    return value

"""
Define codification
"""

### Magic number
magics = {
            '<Unknown>'         : 1/4,
            'MZ'                : 2/4,
            'PE\x00\x00d\x86'   : 3/4,
            '\x7fELF'           : 4/4,
        }

### Filetype
filetypes = {
                'ELF' : 1,
                'MZ'  : 2,
                'PE'  : 2,
           }

### Architecture
architectures = {
                '<unknown>'                         : 1/12,
                'AArch64'                           : 2/12,
                'ARM'                               : 3/12,
                'Advanced Micro Devices X86-64'     : 4/12,
                'Atmel AVR 8-bit microcontroller'   : 5/12,
                'Intel 80386'                       : 6/12,
                'MC68000'                           : 7/12,
                'MIPS R3000'                        : 8/12,
                'PowerPC'                           : 9/12,
                'PowerPC64'                         : 10/12,
                'Sparc'                             : 11/12,
                0x14C                               : 6/12,
                0x8664                              : 4/12,
                0x200                               : 12/12,
                }

### Characteristics
chars = {}
char_list = ['0x0', '0x102', '0x103', '0x106', '0x107', '0x10a', '0x10b', '0x10e', '0x10f', '0x11e', '0x11f', '0x122', '0x123', '0x123f', '0x126', '0x127', '0x12e', '0x12f', '0x147', '0x14f', '0x182', '0x183', '0x186', '0x1d4f', '0x2', '0x2001', '0x2002', '0x2022', '0x2023', '0x2026', '0x202e', '0x20f', '0x2102', '0x2103', '0x2106', '0x210a', '0x210e', '0x210f', '0x211e', '0x2122', '0x212e', '0x2182', '0x22', '0x220c', '0x220e', '0x222', '0x2222', '0x2226', '0x222e', '0x223', '0x226', '0x227', '0x22e', '0x22f', '0x23', '0x2302', '0x2306', '0x230a', '0x230e', '0x232e', '0x26', '0x27', '0x280e', '0x2822', '0x2922', '0x2c22', '0x2d02', '0x2d03', '0x2d0e', '0x2d22', '0x2e', '0x2f', '0x3', '0x302', '0x303', '0x307', '0x30b', '0x30e', '0x30f', '0x322', '0x323', '0x32e', '0x32f', '0x412f', '0x451f', '0x492a', '0x502', '0x50f', '0x8103', '0x812e', '0x8182', '0x818e', '0x818f', '0x81ae', '0x81bf', '0x822', '0x838e', '0x838f', '0x8f8f', '0x922', '0xa022', '0xa023', '0xa0e', '0xa102', '0xa103', '0xa18e', '0xa18f', '0xc22', '0xc23', '0xd02', '0xd03', '0xd0f', '0xd22', '0xd23', '<Unknown>', 'CORE (Core file)', 'DYN (Position-Independent Executable file)', 'DYN (Shared object file)', 'EXEC (Executable file)', 'REL (Relocatable file)']
total = len(char_list)

for index, value in enumerate(char_list):
    chars[value] = (index+1) / total

### Sections
sections = {}
relevant_sections = {'.text', '.data', '.rsrc', '.bss', '.shstrtab', '.rodata', '.init', '.fini', '.ctors', '.dtors', '.reloc', '.rdata', '.comment', '.eh_frame', '.symtab', '.strtab', '.jcr', '.got', '.sbss', '.debug_info', '.gnu_debuglink', '.note.gnu.build-id', '.note.GNU-stack', '.rela.text', '.plt', '.rodata.str1.1', '.dynsym', '.dynstr',}
relevant_sections = set([x.upper() for x in relevant_sections])

total = len(relevant_sections)

for index, value in enumerate(relevant_sections):
    sections[value] = (index+1) / total

### Libraries
libs = {}
relevant_libs = {'KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll', 'GDI32.dll', 'mscoree.dll', 'SHELL32.dll', 'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ole32.dll', 'oleaut32.dll', 'WININET.dll' , 'PSAPI.DLL', 'COMCTL32.dll', 'OLEAUT32.dll', 'CRYPT32.dll', 'WS2_32.dll', 'comctl32.dll', 'MSVCRT.dll', 'SHLWAPI.dll', 'api-ms-win-core-sysinfo-l1-1-0.dll', 'api-ms-win-core-processthreads-l1-1-0.dll', 'api-ms-win-core-errorhandling-l1-1-0.dll', 'api-ms-win-core-profile-l1-1-0.dll', 'api-ms-win-core-libraryloader-l1-2-0.dll', 'api-ms-win-core-synch-l1-2-0.dll', 'api-ms-win-core-synch-l1-1-0.dll', 'api-ms-win-core-handle-l1-1-0.dll', 'api-ms-win-core-heap-l1-1-0.dll', "libc.so.6", "msvcrt.dll", "ntdll.dll", "api-ms-win-core-debug-l1-1-0.dll", "api-ms-win-core-localization-l1-2-0.dll", "api-ms-win-core-registry-l1-1-0.dll", "api-ms-win-core-com-l1-1-0.dll", "api-ms-win-core-string-l1-1-0.dll", "api-ms-win-eventing-provider-l1-1-0.dll"}
relevant_libs = set([x.upper() for x in relevant_libs])

total = len(relevant_libs)

for index, value in enumerate(relevant_libs):
    libs[value] = (index+1) / total

def generic_feat(jsontext):
    """
    Extracts features from a JSON object containing data of binary file.

    Args:
        jsontext (dict): A JSON object containing the required generic data.

    Returns:
        numpy.ndarray: An array containing the extracted features.

    Raises:
        None.
    """

    # MD5
    md5 = int(f"0x{jsontext.get('MD5', 0)}", 0) / 2**128

    # Magic Processing
    magic = jsontext.get("MAGIC", 0.0)
    magic_coded = magics.get(magic, 0.0)

    # Size
    size = jsontext["SIZE"]

    # Type
    filetype = filetypes.get(jsontext.get("TYPE", None) , 0.0)

    # Architecture and Characteristics
    if 'ELF' in magic:
        arch = jsontext.get("STATIC", {}).get("HEADER", {}).get("ARCH", 0.0)
        characteristic = jsontext.get("STATIC", {}).get("HEADER", {}).get("OBJECT_TYPE", None)
    else:
        arch = jsontext.get("STATIC", {}).get("HEADER", {}).get("machine_type", 0.0)
        characteristic = jsontext.get("STATIC", {}).get("HEADER", {}).get("characteristics", None)

    architecture = architectures.get(arch, 0.0)

    # Characteristics
    characteristic = chars.get(characteristic, 0.0)

    # Sections
    current_sections = jsontext.get("STATIC", {}).get("SECTIONS", None)
    if type(current_sections) is list:
        current_sections = [d["name"] for d in current_sections]
    elif type(current_sections) is dict:
        sect = []
        for (key, value) in current_sections.items():
            try:
                if "SECTION_ADDR" in value:
                    sect.append(key)
            except:
                pass

        current_sections = sect

    else:
        current_sections = []

    # Number of sections
    sections_num = len(current_sections)

    # Security
    mitigations = jsontext.get("MITIGATIONS", {})
    mitigations_coded = hash_md5_dict(mitigations)

    # Strings number
    strings_len = len(jsontext.get("COMMON", {}).get("STRINGS", []))

    # Coding sections
    current_dict_section = dict.fromkeys(relevant_sections, 0.0)
    for section in current_sections:
        if section.upper() in sections:
            current_dict_section[section.upper()] = sections[section.upper()]

    # Get libraries
    if 'ELF' in magic:
        dynamic_data = jsontext.get("STATIC", {}).get("DYNAMIC", {})
        currentlibs = dynamic_data.get("SHARED_LIBRARIES", []) + dynamic_data.get("LIBRARIES_SONAME", [])
    else:
        import_table = jsontext.get("STATIC", {}).get("IMPORT_TABLE", [])
        currentlibs = [dll["dll_name"] for dll in import_table]

    # Coding libraries
    current_dict_libs = dict.fromkeys(relevant_libs, 0.0)
    for lib in currentlibs:
        if lib.upper() in libs:
            current_dict_libs[lib.upper()] = libs[lib.upper()]

    data = []
    data.append(md5)
    data.append(magic_coded)
    data.append(size)
    data.append(filetype)
    data.append(architecture)
    data.append(characteristic)
    data.append(sections_num)
    data.append(mitigations_coded)
    data.append(strings_len)
    for key, value in current_dict_section.items():
        data.append(value)
    for key, value in current_dict_libs.items():
        data.append(value)

    return list_to_numpy_array(data)

### Predictors ###

def entropy_predict(jsontext):
    """
    Predict entropy from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    int: Model prediction
    """
    try:
        X = entropy_feat(jsontext)
        X = X.reshape(1, -1)
        entropy_model = load_model(entropy_pkl)
        prediction = int(entropy_model.predict(X)[0])
        return prediction
    except:
        return -1

def functions_predict(jsontext):
    """
    Predict functions from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    int: Model prediction
    """
    try:
        X = functions_feat(jsontext)
        X = X.reshape(1, -1)
        functions_model = load_model(functions_pkl)
        prediction = int(functions_model.predict(X)[0])
        return prediction
    except:
        return -1

def strings_predict(jsontext):
    """
    Predict strings from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    int: Model prediction
    """
    try:
        X = strings_feat(jsontext)
        X = X.reshape(1, -1)
        strings_model = load_model(strings_pkl)
        prediction = int(strings_model.predict(X)[0])
        return prediction
    except:
        return -1

def generic_predict(jsontext):
    """
    Predict generic features from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    int: Model prediction
    """
    try:
        X = generic_feat(jsontext)
        X = X.reshape(1, -1)
        generic_model = load_model(generic_pkl)
        prediction = int(generic_model.predict(X)[0])
        return prediction
    except:
        return -1

def mnemonics_predict(jsontext):
    """
    Predict mnemonics from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    int: Model prediction
    """
    try:
        X = mnemonics_feat(jsontext)
        X = X.reshape(1, -1)
        mnemonics_model = load_model(mnemonics_pkl)
        prediction = int(mnemonics_model.predict(X)[0])
        return prediction
    except:
        return -1


### Bin Sniff utils ###

def init_binsniff(binarypath, static_only, timeout=None, output="/tmp/"):
    """
    Initializes a BinSniff object with the specified parameters.

    Args:
        binarypath (str): Path to the binary to be analyzed.
        static_only (bool): If True, only static analysis will be performed.
        verbosity (int, optional): The level of logging verbosity. Defaults to 3.
        timeout (int, optional): Maximum time to allow for the operation.
                                 If None, there is no timeout.
        output (str, optional): Path to the directory for output files. Defaults to "/tmp/".

    Returns:
        binsniff.BinSniff: A BinSniff object initialized with the specified parameters.
    """

    binsniff_obj = binsniff.BinSniff(   binarypath,
                                        output,
                                        verbosity=0,
                                        timeout=timeout,
                                        only_static=static_only,
                                    )

    return binsniff_obj

def static_predictions(sniffer_data):
    """
    Predicts various aspects of the given sniffer data.

    Args:
        sniffer_data (dict): A dictionary of sniffer data to analyze.

    Returns:
        dict: A dictionary with keys as the prediction categories and values as the predictions.
    """

    foo = functions_predict(sniffer_data)
    entropy = entropy_predict(sniffer_data)
    strings = strings_predict(sniffer_data)
    generic = generic_predict(sniffer_data)

    return {"functions": foo,
            "entropy" : entropy,
            "strings" : strings,
            "generic" : generic}

def simple_voting_system(binarypath, verbosity=3, timeout=None):
    """
    Performs a hard voting system to determine if a binary is malware.

    The function initializes a BinSniff object, extracts features, makes
    predictions, and uses these to determine if the binary is malware.
    If it can't determine, it re-initializes the BinSniff object for non-static
    analysis and adds the mnemonics model to the list.

    Args:
        binarypath (str): Path to the binary to be analyzed.
        verbosity (int, optional): The level of logging verbosity.
                                   Defaults to 3.
        timeout (int, optional): Maximum time to allow for the operation.
                                 If None, there is no timeout.

    Returns:
        tuple: A tuple with the first element as the results dictionary,
               and the second element as a boolean indicating if the sum
               of values is greater than 2 (indicative of being malware).
    """

    static_sniffer = init_binsniff(binarypath, True)
    features = static_sniffer.extract_features()[0]
    static_results = static_predictions(features)

    if list(static_results.values()).count(0) > 2 or list(static_results.values()).count(1) > 2:
        return (static_results, sum(list(static_results.values())) > 2)

    if verbosity>0:
        log("w", "Insufficient 4 votes to confirm malware; MNEMONICS model added to list.")

    del static_sniffer
    sniffer =  init_binsniff(binarypath, False, timeout=timeout)
    features = sniffer.extract_features()[0]
    static_results.update({"mnemonics" : mnemonics_predict(features)})
    results = static_results.copy()

    return (results, sum(list(static_results.values())) > 2)

### Probabilistic Methods ###

### Predictors ###

def entropy_prob_predict(jsontext):
    """
    Predict entropy from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    dict: Model prediction probabilities
    """
    try:
        X = entropy_feat(jsontext)
        X = X.reshape(1, -1)
        entropy_model = load_model(entropy_pkl)
        prediction_probs = entropy_model.predict_proba(X)[0]
        return {i: prob for i, prob in enumerate(prediction_probs)}
    except:
        return -1

def functions_prob_predict(jsontext):
    """
    Predict functions from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    dict: Model prediction probabilities
    """
    try:
        X = functions_feat(jsontext)
        X = X.reshape(1, -1)
        functions_model = load_model(functions_pkl)
        prediction_probs = functions_model.predict_proba(X)[0]
        return {i: prob for i, prob in enumerate(prediction_probs)}
    except:
        return -1

def strings_prob_predict(jsontext):
    """
    Predict strings from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    dict: Model prediction probabilities
    """
    try:
        X = strings_feat(jsontext)
        X = X.reshape(1, -1)
        strings_model = load_model(strings_pkl)
        prediction_probs = strings_model.predict_proba(X)[0]
        return {i: prob for i, prob in enumerate(prediction_probs)}
    except:
        return -1

def generic_prob_predict(jsontext):
    """
    Predict generic features from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    dict: Model prediction probabilities
    """
    try:
        X = generic_feat(jsontext)
        X = X.reshape(1, -1)
        generic_model = load_model(generic_pkl)
        prediction_probs = generic_model.predict_proba(X)[0]
        return {i: prob for i, prob in enumerate(prediction_probs)}
    except:
        return -1

def mnemonics_prob_predict(jsontext):
    """
    Predict mnemonics from json text.

    Parameters:
    jsontext (str): JSON text input

    Returns:
    dict: Model prediction probabilities
    """
    try:
        X = mnemonics_feat(jsontext)
        X = X.reshape(1, -1)
        mnemonics_model = load_model(mnemonics_pkl)
        prediction_probs = mnemonics_model.predict_proba(X)[0]
        return {i: prob for i, prob in enumerate(prediction_probs)}
    except:
        return -1

def prob_predictions(sniffer_data):
    """
    Predicts various aspects of the given sniffer data.

    Args:
        sniffer_data (dict): A dictionary of sniffer data to analyze.

    Returns:
        dict: A dictionary with keys as the prediction categories and values
              as the predictions.
    """

    foo = functions_prob_predict(sniffer_data)
    entropy = entropy_prob_predict(sniffer_data)
    strings = strings_prob_predict(sniffer_data)
    generic = generic_prob_predict(sniffer_data)
    mnemonics = mnemonics_prob_predict(sniffer_data)

    return {"functions": foo,
            "entropy" : entropy,
            "strings" : strings,
            "generic" : generic,
            "mnemonics" : mnemonics,}


def probabilistic_system(binarypath, timeout=None):
    """
    This function performs a probabilistic analysis on a binary executable using
    a static sniffer. It first initializes the static sniffer with the provided
    binary path and then extracts features from the binary. Finally,
    it calculates and returns the probabilistic predictions based on the
    extracted features.

    Args:
        binarypath (str): The path to the binary file that should be analyzed.
        timeout (int, optional): The maximum time to get CFG in mnemonics
                                 analysis.

    Returns:
        list: The results of the probabilistic predictions on the binary's
              extracted features.

    Raises:
        TimeoutError: If the sniffer does not finish within the specified
                      timeout.
    """

    static_sniffer = init_binsniff(binarypath, False, timeout=timeout)
    features = static_sniffer.extract_features()[0]
    static_prob_results = prob_predictions(features)

    return static_prob_results
