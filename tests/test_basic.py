import pytest

from coredumplib import code_id_to_debug_id
from coredumplib import get_frame
from coredumplib import Frame
from coredumplib import get_image
from coredumplib import Image
from coredumplib import main


def test_code_id_to_debug_id():
    assert (
        code_id_to_debug_id("a05fd1a285ff0547ece8cb2aced6d59885852230")
        == "a2d15fa0-ff85-4705-ece8-cb2aced6d598"
    )


@pytest.mark.parametrize(
    "gdb_output, parsed",
    [
        [
            "0  0x000055ee7d69e60a in crashing_function () at ./test.c:3",
            Frame(
                instruction_addr="0x000055ee7d69e60a",
                name_of_function="crashing_function",
                path="./test.c",
                lineno=3,
            ),
        ],
        [
            "1  0x000055ee7d69e61c in main () at ./test.c:7",
            Frame(
                instruction_addr="0x000055ee7d69e61c",
                name_of_function="main",
                path="./test.c",
                lineno=7,
            ),
        ],
        [
            "0  0x000055a7df18760a in crashing_function ()",
            Frame(
                instruction_addr="0x000055a7df18760a",
                name_of_function="crashing_function",
                path="abs_path",
                lineno=None,
            ),
        ],
        [
            "#1 0x0000748f47a34256 in <test::function as test::function>::event ()",
            Frame(
                instruction_addr="0x0000748f47a34256",
                name_of_function="event",
                path="abs_path",
                lineno=None,
            ),
        ],
        [
            "#1 0x0000748f47a34256 in test::function as test::function::event ()",
            Frame(
                instruction_addr="0x0000748f47a34256",
                name_of_function="event",
                path="abs_path",
                lineno=None,
            ),
        ],
    ],
)
def test_get_frame(gdb_output, parsed):

    frame_test = get_frame(gdb_output)

    assert frame_test.instruction_addr == parsed.instruction_addr
    assert frame_test.name_of_function == parsed.name_of_function
    assert frame_test.lineno == parsed.lineno
    assert frame_test.path == parsed.path


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
    image_test = get_image(unstrip_output)

    assert image_test.code_file == parsed.code_file
    assert image_test.code_id == parsed.code_id
    assert image_test.image_addr == parsed.image_addr
    assert image_test.image_size == parsed.image_size


def test_frame_to_json():
    frame = Frame()
    assert frame.to_json() == {
        "instruction_addr": "",
        "lineno": None,
        "name_of_function": "",
        "path": "abs_path",
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
