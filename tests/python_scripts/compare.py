import sys
import json

# CONSTS
ignore = [ "version", "release", "handle" ]

#TODO:
#How to handle real data
#Figure Out Where Expected and got are coming from


def compare(expected: dict, got: dict) -> int:
    #O(N)
    for key in expected:
        expected_val = expected[key]
        got_val = got[key]

        if key in ignore:
            continue
        #Missing Key
        elif key not in got:# Fail
            return 1
        #Type Diff
        elif type(expected_val) != type(got_val): # Fail
            return 1
        #Value Diff
        elif expected_val != got_val:
            return 1
        #Found Dict and we need to go Call on sub-object
        elif type(expected_val) == (type({}) or type([])):
            print("Going Depper")
            #O(m)
            if compare(expected_val, got_val): # Fail else Pass
                return 1
        #else: we move on

    #if loops dont return early we pass
    return 0

#This is just for testing atm; not how real data will come in
if __name__ == "__main__":
    file = open(sys.argv[1], 'r')
    json_data = json.load(file)
    print("OUTCOME: ", compare(json_data,json_data))
