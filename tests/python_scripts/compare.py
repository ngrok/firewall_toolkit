from typing import Any
import sys
import json

ignore: list[str] = [ "metainfo", "handle" ]

def compare(expected: dict[str,Any], got: dict[str,Any]) -> int:
    for expected_key,got_key in zip(expected,got):
        expected_val: Any = expected[expected_key]
        got_val: Any = got[got_key]

        match (expected_key,got_key):
            case _ as keys if keys[0] != keys[1]:
                return 1
            case _ as keys if keys[0] in ignore:
                continue
            case _ as keys if expected_val != got_val:
                return 1
            case _ as keys if type(expected_val) == type({}):
                if compare(expected_val,got_val) == 1: return 1
            case _ as keys if type(expected_val) == type([]):
                for v1,v2 in zip(expected_val,got_val):
                    if type(v1) == type({}):
                        if compare(v1,v2) == 1:
                            return 1
                    elif v1 != v2:
                        return 1
            case _:
                continue
    return 0

if __name__ == "__main__":
    expected: dict[str,Any] = json.load(sys.stdin)
    got: dict[str,Any] = json.load(open(sys.argv[1], 'r'))
    val: int = compare(expected,got)
    print(val)
