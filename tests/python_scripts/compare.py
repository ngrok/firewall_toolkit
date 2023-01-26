from typing import Any

import sys
import json

ignore: list[str] = [ "version", "release", "handle" ]

#TODO:
#How to handle real data
#Figure Out Where Expected and got are coming from
#What if got has keys not in expected? should I bring back the 2nd for loop or
def compare(expected: dict, got: dict) -> int:
    #O(N)
    for k1,k2 in zip(expected,got):
        expected_val: Any = expected[k1]
        got_val: Any = got[k2]
        match (k1,k2):
            case _ as k if k[0] != k[1]:
                return 1
            case _ as k if k[0] in ignore:
                continue
            # case _ as k if type(expected_val) != type(got_val):
            #     return 1
            case _ as k if expected_val != got_val:
                return 1
            # <class 'dict'> == <class 'dict>
            case _ as k if type(expected_val) == type({}):
                if compare(expected_val,got_val) == 1:
                    return 1
            #kind sketchy ngl
            #[ {} , {} , {} ] e
            #[ {} , {} , {} ] g
            case _ as k if type(expected_val) == type([]):
                for v1,v2 in zip(expected_val,got_val):
                    if type(v1) == type({}):
                        if compare(v1,v2) == 1:
                            return 1
                    elif v1 != v2:
                        return 1

            case _:
                continue
    return 0

#This is just for testing atm; not how real data will come in
if __name__ == "__main__":
    expected: dict = json.load(sys.stdin)
    got: dict = json.load(open(sys.argv[1], 'r'))
    val: int = compare(expected,got)
    print(val)
    # file = open(sys.argv[1], 'r')
    # json_data = json.load(file)
    # print("OUTCOME: ", compare(json_data,json_data))
