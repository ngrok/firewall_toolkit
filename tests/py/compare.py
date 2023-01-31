from typing import Any, Optional
import sys
import json

ignore: list[str] = [ "metainfo", "handle" ]

def value_error(key: str) -> tuple[int,str]:
    msg : str = "FAIL: values do not match in " + key
    return (1, msg)

def key_error(keys: Optional[tuple[str,str]]) -> tuple[int,str]:
    if keys is None:
        msg: str = "FAIL: key not found in expected"
    else:
        msg : str = "FAIL: keys do not match. expected: " + keys[0] + " received: " + keys[1]
    return (1, msg)



def compare(expected: dict[str,Any], received: dict[str,Any]) -> tuple[int,str]:
    for expected_key,received_key in zip(expected,received):
        expected_val: Any = expected[expected_key]
        received_val: Any = received[received_key]
        match (expected_key,received_key):
            case _ as keys if keys[0] != keys[1]:
                return key_error(keys)
            case _ as keys if keys[0] in ignore:
                continue
            case _ as keys if expected_val != received_val:
                return value_error(keys[0])

            case _ as keys if type(expected_val) == type({}):
                child_dict_ouput: tuple[int,str] = compare(expected_val,received_val)
                if child_dict_ouput[0] == 1:
                    return child_dict_ouput

            case _ as keys if type(expected_val) == type([]):
                for e,r in zip(expected_val,received_val):
                    if type(e) == type({}):
                         child_dict_ouput: tuple[int,str] = compare(e,r)
                         if child_dict_ouput[0] == 1:
                             return child_dict_ouput
                    elif e != r:
                        return value_error(e)
            case _:
                continue

    for received_key in received:
        if received_key not in expected:
            return key_error(None)

    return (0,"PASS: exited successfully")


if __name__ == "__main__":
    expected : dict[str,Any] = json.load(open(sys.argv[1], 'r'))
    received : dict[str,Any] = json.load(sys.stdin)
    val: tuple[int,str] = compare(expected,received)
    sys.stdout.write(val[1] + "\n")
    sys.exit(val[0])
