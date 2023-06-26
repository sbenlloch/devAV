import lz4.frame
import hashlib
import json
import glob
import sys
import os


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

def load_features(featurefile):
    return load_compressed_json(featurefile)

def hash_md5_dict(dic):
    string = str(sorted(dic.items()))

    md5_hash = hashlib.md5(string.encode()).hexdigest()
    value = int(md5_hash, 16) / (2 ** 128)  # Size of MD5 in bits is 128

    return value

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <dataset_folder> <data file>")
    sys.exit(1)

dataset = os.path.abspath(sys.argv[1])

"""
Define codification
"""
# If the value is not found, 0
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

for featurefile in glob.glob('**/features.json.lz4', recursive=True, root_dir=dataset):
    data = load_features(featurefile)
    output_file = f"{dataset}/{os.path.dirname(featurefile)}/generic.feature"

    # MD5
    md5 = int(f"0x{data.get('MD5', 0)}", 0) / 2**128

    # Magic Processing
    magic = data.get("MAGIC", 0.0)
    magic_coded = magics.get(magic, 0.0)

    # Size
    size = data["SIZE"]

    # Type
    filetype = filetypes.get(data.get("TYPE", None) , 0.0)

    # Architecture and Characteristics
    if 'ELF' in magic:
        arch = data.get("STATIC", {}).get("HEADER", {}).get("ARCH", 0.0)
        characteristic = data.get("STATIC", {}).get("HEADER", {}).get("OBJECT_TYPE", None)
    else:
        arch = data.get("STATIC", {}).get("HEADER", {}).get("machine_type", 0.0)
        characteristic = data.get("STATIC", {}).get("HEADER", {}).get("characteristics", None)

    architecture = architectures.get(arch, 0.0)

    # Characteristics
    characteristic = chars.get(characteristic, 0.0)

    # Sections
    current_sections = data.get("STATIC", {}).get("SECTIONS", None)
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
    mitigations = data.get("MITIGATIONS", {})
    mitigations_coded = hash_md5_dict(mitigations)

    # Strings number
    strings_len = len(data.get("COMMON", {}).get("STRINGS", []))

    # Coding sections
    current_dict_section = dict.fromkeys(relevant_sections, 0.0)
    for section in current_sections:
        if section.upper() in sections:
            current_dict_section[section.upper()] = sections[section.upper()]

    # Get libraries
    if 'ELF' in magic:
        dynamic_data = data.get("STATIC", {}).get("DYNAMIC", {})
        currentlibs = dynamic_data.get("SHARED_LIBRARIES", []) + dynamic_data.get("LIBRARIES_SONAME", [])
    else:
        import_table = data.get("STATIC", {}).get("IMPORT_TABLE", [])
        currentlibs = [dll["dll_name"] for dll in import_table]

    # Coding libraries
    current_dict_libs = dict.fromkeys(relevant_libs, 0.0)
    for lib in currentlibs:
        if lib.upper() in libs:
            current_dict_libs[lib.upper()] = libs[lib.upper()]

    # Prepare dictionary to dump as JSON
    json_dict = {
        "md5": md5,
        "magic": magic_coded,
        "size": size,
        "filetype": filetype,
        "architecture": architecture,
        "characteristic": characteristic,
        "sections_num": sections_num,
        "mitigations": mitigations_coded,
        "strings_len": strings_len,
        "sections": current_dict_section.copy(),
        "libs": current_dict_libs.copy(),
    }

    # Dump dictionary to JSON file
    with open(output_file, 'w') as outfile:
        j = json.dumps(json_dict, indent=4)
        outfile.write(j)

    print(f"Dump {output_file}")

