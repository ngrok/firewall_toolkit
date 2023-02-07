from typing import Any, Optional
import sys
import json


ignore: list[str] = [ "metainfo", "handle" ]
def err_handler(key: Optional[str], keys: Optional[tuple[str,str]], e: Optional[int] , r: Optional[int]) -> tuple[int, str]:
    if key:
        msg : str = "FAIL: values of key: \"" + key + "\" do not match"
        return (1, msg)
    elif keys:
        msg : str = "FAIL: keys do not match. expected: \"" + keys[0] + "\" received: \"" + keys[1] + "\""
        return (1, msg)
    elif e:
        return (1, "FAIL: given dicts of differnt len. expected: " + str(e) + " received: " + str(r))

    return (1, "FAIL: given dict of len: 0")

def compare(expected: dict[str,Any], received: dict[str,Any]) -> tuple[int,str]:
    """Return a tuple(exit_code,exit_message) from the result of comparing 2 dicts
    >>> compare({ "a" : 1 }, { "a" : 2 })
    (1, 'FAIL: values of key: "a" do not match')
    >>> compare({ "metainfo" : 1 , "a" : 2 }, { "metainfo" : 2, "a" : 1 })
    (1, 'FAIL: values of key: "a" do not match')
    >>> compare({ "b" : 1 }, { "a" : 1 })
    (1, 'FAIL: keys do not match. expected: "b" received: "a"')
    >>> compare({ "handle" : 1 , "b" : 1 }, { "handle" : 2, "a" : 1 })
    (1, 'FAIL: keys do not match. expected: "b" received: "a"')
    >>> compare({ "a" : 1, "b": 1 }, { "a" : 1 })
    (1, 'FAIL: given dicts of differnt len. expected: 2 received: 1')
    >>> compare({ "a" : 1 }, {})
    (1, 'FAIL: given dict of len: 0')
    >>> compare({}, { "a" : 1 })
    (1, 'FAIL: given dict of len: 0')
    >>> compare({ "a": [{1:1},{1:2},{1:1},{1:4}] }, { "a": [{1:1},{1:2},{1:3},{1:4}]})
    (1, 'FAIL: values of key: "1" do not match')
    >>> compare({ 1 : { 2 : 2, 4 : 5 }}, { 1 : { 2 : 3, 4 : 5 }})
    (1, 'FAIL: values of key: "2" do not match')
    >>> compare({ 1 : { 2 : 3, 4 : 5 }}, { 1 : { 2 : 3, 4 : 5 }})
    (0, 'PASS: exited successfully')
    >>> compare({ "a": [{1:1},{1:2},{1:3},{1:4}] }, { "a": [{1:1},{1:2},{1:3},{1:4}]})
    (0, 'PASS: exited successfully')
    >>> compare({ "a": [{},{},{},{}] }, { "a": [{},{},{},{}]})
    (0, 'PASS: exited successfully')
    >>> compare({ "a" : 1 }, { "a" : 1 })
    (0, 'PASS: exited successfully')
    >>> compare({ "metainfo" : 1 , "a" : 1 }, { "metainfo" : 2, "a" : 1 })
    (0, 'PASS: exited successfully')
    """

    if len(expected) == 0 and len(received) == 0:
        return (0,"PASS: exited successfully")
    elif len(expected) == 0 or len(received) == 0:
        return err_handler(None,None,None,None)
    elif len(expected) != len(received):
        return err_handler(None,None,len(expected),len(received))
    #else
    for expected_key, received_key in zip(expected, received):
        expected_val: Any = expected[expected_key]
        received_val: Any = received[received_key]
        #key Checking
        match (expected_key,received_key):
            case _ as keys if keys[0] != keys[1]:
                return err_handler(None,keys,None,None)
                # return key_error(keys)
            case _ as keys if keys[0] in ignore:
                continue
        #value checking
        match (expected_val,received_val):
            case _ as vals if type(vals[0]) == type({}):
                child_dict_ouput: tuple[int,str] = compare(vals[0],vals[1])
                if child_dict_ouput[0] == 1:
                    return child_dict_ouput
            case _ as vals if type(vals[0]) == type([]):
                for v1,v2 in zip(vals[0],vals[1]):
                    if type(v1) == type({}):
                         child_dict_ouput: tuple[int,str] = compare(v1,v2)
                         if child_dict_ouput[0] == 1:
                             return child_dict_ouput
                    elif v1 != v2:
                        return err_handler(str(v1),None,None,None)
                        # return value_error(v1)
            case _ as vals if vals[0] != vals[1]:
                return err_handler(str(expected_key),None,None,None)
                # return value_error(expected_key)

    return (0,"PASS: exited successfully")


if __name__ == "__main__":
    expected : dict[str, Any] = json.load(open(sys.argv[1], 'r'))
    received : dict[str, Any] = json.load(sys.stdin)
    val: tuple[int, str] = compare(expected, received)
    sys.stdout.write(val[1] + "\n")
    sys.exit(val[0])
