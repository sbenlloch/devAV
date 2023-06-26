import json
import sys

def get_n_largest_keys(dictionary, n):
    tuple_list = list(dictionary.items())
    sorted_tuple_list = sorted(tuple_list, key=lambda x: x[1], reverse=True)
    n_largest_tuples = sorted_tuple_list[:n]
    n_largest_keys = [tup[0] for tup in n_largest_tuples]
    return n_largest_keys

with open(sys.argv[1], "r") as f:
    j = json.loads(f.read())

instructions = j["counter"]

N = int(sys.argv[2])

functions = get_n_largest_keys(instructions, N)

def group_functions(function_list):
    function_dict = {}
    for func1 in function_list:
        base_name = func1
        for func2 in function_list:
            if func1 != func2 and func1 in func2:
                base_name = func2
                break

        if base_name not in function_dict:
            function_dict[base_name] = []

        function_dict[base_name].append(func1)

    return function_dict

print(group_functions(functions))
