import sys

# CONSTS
ignore = [ "version", "release", "handle" ]

#TODO:
#Main Recursive Logic
def compare(expected: dict, got: dict) -> int:
    for key in expected:
        expected_val = expected[key]
        got_val = got[key]

        if key in ignore:
            continue
        #Missong Key
        elif key not in got:# Fail
            return 1
        #Type Diff
        elif type(expected_val) != type(got_val): # Fail
            return 1
        #Value Diff
        elif expected_val != got_val:
            return 1
        #Found Dict and we need to go Call on sub-object
        elif type(expected_val) == type({}):
            if compare(expected_val, got_val): # Fail else Pass
                return 1

    for key in got:
        if key in ignore:
            continue
        if key not in expected:
            return 1
    #if loop exits we pass
    return 0

