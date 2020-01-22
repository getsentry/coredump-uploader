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
    image = Image()
    assert image.to_json() == {
        "type": "",
        "image_addr": "",
        "image_size": "",
        "debug_id": "",
        "code_id": "",
        "code_file": "",
    }


def test_stacktrace_to_json():
    frame = Frame(
        instruction_addr="0x0000748f47a34256",
        function="test::function as test::function::event",
        filename=None,
        lineno=None,
    )
    stacktrace = Stacktrace()
    stacktrace.append_frame(frame.to_json())
    assert stacktrace.to_json() == {
        "frames": [
            {
                "instruction_addr": "0x0000748f47a34256",
                "function": "test::function as test::function::event",
                "filename": None,
                "lineno": None,
                "package": None,
            }
        ]
    }


def test_thread_to_json():
    stacktrace = Stacktrace()
    thread = Thread(9, None, False, stacktrace.to_json())
    assert thread.to_json() == {
        "stacktrace": {"frames": []},
        "id": 9,
        "name": None,
        "crashed": False,
    }
