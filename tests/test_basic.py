import pytest
import re

from coredump_uploader import code_id_to_debug_id
from coredump_uploader import get_frame
from coredump_uploader import Frame
from coredump_uploader import get_image
from coredump_uploader import Image
from coredump_uploader import main
from coredump_uploader import _frame_re
from coredump_uploader import _image_re
from coredump_uploader import Thread
from coredump_uploader import Stacktrace
from coredump_uploader import main
from coredump_uploader import get_all_threads


def test_code_id_to_debug_id():
    assert (
        code_id_to_debug_id("a05fd1a285ff0547ece8cb2aced6d59885852230")
        == "a2d15fa0-ff85-4705-ece8-cb2aced6d598"
    )


@pytest.mark.parametrize(
    "gdb_output, parsed",
    [
        [
            "#0  0x000055ee7d69e60a in crashing_function () at ./test.c:3",
            Frame(
                instruction_addr="0x000055ee7d69e60a",
                function="crashing_function",
                filename="./test.c",
                lineno=3,
            ),
        ],
        [
            "#2  0x000055a7df18760a in std::test::read () from /lib/x86_64-linux-gnu/libc.so.6",
            Frame(
                instruction_addr="0x000055a7df18760a",
                function="std::test::read",
                filename=None,
                lineno=None,
                package="/lib/x86_64-linux-gnu/libc.so.6",
            ),
        ],
        [
            "#0  0x000055a7df18760a in crashing_function ()",
            Frame(
                instruction_addr="0x000055a7df18760a",
                function="crashing_function",
                filename=None,
                lineno=None,
            ),
        ],
        [
            "#1 0x0000748f47a34256 in <test::function as test::function>::event ()",
            Frame(
                instruction_addr="0x0000748f47a34256",
                function="<test::function as test::function>::event",
                filename=None,
                lineno=None,
            ),
        ],
        [
            "#1 0x0000748f47a34256 in test::function as test::function::event ()",
            Frame(
                instruction_addr="0x0000748f47a34256",
                function="test::function as test::function::event",
                filename=None,
                lineno=None,
            ),
        ],
        [
            "#2  0x000055ee7d69e60a in std::test::read(char*) () from /usr/lib/x86_64-linux-gnu/libstdc++.so.6",
            Frame(
                instruction_addr="0x000055ee7d69e60a",
                function="std::test::read(char*)",
                filename=None,
                lineno=None,
                package="/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
            ),
        ],
    ],
)
def test_get_frame(gdb_output, parsed):
    for match in re.finditer(_frame_re, gdb_output):
        frame_test = get_frame(match)

    assert frame_test.instruction_addr == parsed.instruction_addr
    assert frame_test.function == parsed.function
    assert frame_test.lineno == parsed.lineno
    assert frame_test.filename == parsed.filename


@pytest.mark.parametrize(
    "unstrip_output,parsed",
    [
        [
            "0x7ffedbaee000+0x1000 09e243c2fb482669406caba88fad799413f2a375@0x7ffedbaee7c0 . - linux-vdso.so.1",
            Image(
                code_file="linux-vdso.so.1",
                code_id="09e243c2fb482669406caba88fad799413f2a375",
                image_addr="0x7ffedbaee000",
                image_size=4096,
            ),
        ],
        [
            "0x55ee7d69e000+0x201018 b814d9f87debe4b312c06a03fa8d6b44a7b41199@0x55ee7d69e284 ./a.out . a.out",
            Image(
                code_file="/a.out",
                code_id="b814d9f87debe4b312c06a03fa8d6b44a7b41199",
                image_addr="0x55ee7d69e000",
                image_size=2101272,
            ),
        ],
        [
            "0x7fb45a61f000+0x3f0ae0 b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0@0x7fb45a61f280 /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so libc.so.6",
            Image(
                code_file="/lib/x86_64-linux-gnu/libc.so.6",
                code_id="b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0",
                image_addr="0x7fb45a61f000",
                image_size=4131552,
            ),
        ],
    ],
)
def test_get_image(unstrip_output, parsed):
    image_test = Image()
    for match in re.finditer(_image_re, unstrip_output):
        image_test = get_image(match)

    assert image_test.code_file == parsed.code_file
    assert image_test.code_id == parsed.code_id
    assert image_test.image_addr == parsed.image_addr
    assert image_test.image_size == parsed.image_size


def test_frame_to_json():
    frame = Frame()
    assert frame.to_json() == {
        "instruction_addr": None,
        "lineno": None,
        "function": None,
        "filename": None,
        "package": None,
    }


def test_image_to_json():
    image = Image(
        None,
        "0x7fb45a61f000",
        "4131552",
        None,
        "b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0",
        "/lib/x86_64-linux-gnu/libc.so.6",
    )
    assert image.to_json() == {
        "type": None,
        "image_addr": "0x7fb45a61f000",
        "image_size": "4131552",
        "debug_id": None,
        "code_id": "b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0",
        "code_file": "/lib/x86_64-linux-gnu/libc.so.6",
    }


def test_stacktrace_to_json():
    frame = Frame(
        instruction_addr="0x0000748f47a34256",
        function="test::function as test::function::event",
        filename=None,
        lineno=None,
    )
    stacktrace = Stacktrace()
    stacktrace.append_frame(frame)
    assert stacktrace.to_json() == {
        "frames": [
            {
                "instruction_addr": "0x0000748f47a34256",
                "function": "test::function as test::function::event",
                "filename": None,
                "lineno": None,
                "package": None,
            }
        ],
        "registers": {},
    }


def test_thread_to_json():
    thread = Thread(9, "test", False, Stacktrace())
    assert thread.to_json() == {
        "stacktrace": {"frames": [], "registers": {}},
        "id": 9,
        "name": "test",
        "crashed": False,
    }


@pytest.mark.parametrize(
    "gdb_output",
    [
        """ 
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://w    ww.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from a.out...done.
[New LWP 3421]
Core was generated by `./a.out'.
[Current thread is 1 (LWP 3421)]
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000055931ccfe60a in crashing_function () at test.c:3
3	  *bad_pointer = 1;
(gdb)
Thread 1 (LWP 3421):
#0  0x000055931ccfe60a in crashing_function () at test.c:3
#1  0x000055931ccfe61c in main () at test.c:7

Thread 2 (LWP 45):
#0  0x00005594565cfeab in test_function () at test_file.c:7
#1  0x0000563f31ccfafc in test () at test_file.c:9

Thread 3 (Thread 0x5846 (LWP 40)):
#0  0x00005594565cfeab in test_function () at test_file.c:7
#2  0x000055a7df18760a in std::test::read () from /lib/x86_64-linux-gnu/libc.so.6
(gdb) quit
            """
    ],
)
def test_get_all_threads(gdb_output):
    ls, exit_signal = get_all_threads(gdb_output)
    assert exit_signal == "SIGSEGV"
    assert ls[2].to_json() == {
        "id": "1",
        "name": "LWP 3421",
        "crashed": True,
        "stacktrace": {
            "frames": [
                {
                    "instruction_addr": "0x000055931ccfe61c",
                    "function": "main",
                    "filename": "test.c",
                    "lineno": 7,
                    "package": None,
                },
                {
                    "instruction_addr": "0x000055931ccfe60a",
                    "function": "crashing_function",
                    "filename": "test.c",
                    "lineno": 3,
                    "package": None,
                },
            ],
            "registers": {},
        },
    }

    assert ls[1].to_json() == {
        "id": "2",
        "name": "LWP 45",
        "crashed": False,
        "stacktrace": {
            "frames": [
                {
                    "instruction_addr": "0x0000563f31ccfafc",
                    "function": "test",
                    "filename": "test_file.c",
                    "lineno": 9,
                    "package": None,
                },
                {
                    "instruction_addr": "0x00005594565cfeab",
                    "function": "test_function",
                    "filename": "test_file.c",
                    "lineno": 7,
                    "package": None,
                },
            ],
            "registers": {},
        },
    }

    assert ls[0].to_json() == {
        "id": "3",
        "name": "LWP 40",
        "crashed": False,
        "stacktrace": {
            "frames": [
                {
                    "instruction_addr": "0x000055a7df18760a",
                    "function": "std::test::read",
                    "filename": None,
                    "lineno": None,
                    "package": "/lib/x86_64-linux-gnu/libc.so.6",
                },
                {
                    "instruction_addr": "0x00005594565cfeab",
                    "function": "test_function",
                    "filename": "test_file.c",
                    "lineno": 7,
                    "package": None,
                },
            ],
            "registers": {},
        },
    }
