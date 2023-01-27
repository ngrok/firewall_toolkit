from typing import Any
import sys
import json

ignore: list[str] = [ "metainfo", "handle" ]

def compare(expected: dict[str,Any], got: dict[str,Any]) -> tuple[int,str]:
    for expected_key,got_key in zip(expected,got):
        expected_val: Any = expected[expected_key]
        got_val: Any = got[got_key]
        match (expected_key,got_key):
            case _ as keys if keys[0] != keys[1]:
                msg : str = "FAIL: keys do not match. expected: " + keys[0] + " got: " + keys[1]
                return (1, msg)

            case _ as keys if keys[0] in ignore:
                continue

            case _ as keys if expected_val != got_val:
                msg : str = "FAIL: values do not match."
                if type(expected_val) != (type({}) and type([])):
                    msg += " expected: " + str(expected_val) + " got: " + str(got_val)
                else:
                    msg += " diff inside of " + str(type(expected_val)) + " type"
                return (1, msg)

            case _ as keys if type(expected_val) == type({}):
                child_dict_ouput: tuple[int,str] = compare(expected_val,got_val)
                if child_dict_ouput[0] == 1:
                    return child_dict_ouput

            case _ as keys if type(expected_val) == type([]):
                for v1,v2 in zip(expected_val,got_val):
                    if type(v1) == type({}):
                         child_dict_ouput: tuple[int,str] = compare(v1,v2)
                         if child_dict_ouput[0] == 1:
                             return child_dict_ouput
                    elif v1 != v2:
                        msg : str = "FAIL: values do not match"
                        if type(v1) != (type({}) and type([])):
                            msg += " expected: " + str(v1) + " got: " + str(v2)
                        else:
                             msg += " diff inside of " + str(type(v1)) + " type"
                        return (1,msg)
            case _:
                continue

    for got_key in got:
        if got_key not in expected:
            msg: str = "FAIL: key not found in expected nftable"
            return (1, msg)

    return (0,"PASS: exited successfully")


if __name__ == "__main__":
    expected: dict[str,Any] = json.load(sys.stdin)
    got: dict[str,Any] = json.load(open(sys.argv[1], 'r'))
    val: tuple[int,str] = compare(expected,got)
    sys.exit(val[0])
