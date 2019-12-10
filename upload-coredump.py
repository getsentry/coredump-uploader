import re
import sentry_sdk
import binascii
import uuid
import subprocess
import sys
import os
import click
import time


class Frame:
    def __init__(self, instruction_addr="", name_of_function="", path="", lineno=""):
        self.instruction_addr = instruction_addr
        self.name_of_function = name_of_function
        self.path = path
        self.lineno = lineno

    def to_json(self):
        return self.__dict__


class Image:
    def __init__(
        self,
        type="",
        image_addr="",
        image_size="",
        debug_id="",
        code_id="",
        code_file="",
    ):
        self.type = type
        self.image_addr = image_addr
        self.image_size = image_size
        self.debug_id = debug_id
        self.code_id = code_id
        self.code_file = code_file

    def to_json(self):
        return self.__dict__


_frame_re = re.compile(
    r"""(?x)
    
    #address of instruction
    (?P<instruction_addr>
       0[xX][a-fA-F0-9]+
    )
    #name of function
    (\sin)? \s?
    (?P<name_of_function>
        [a-zA-z]+
    )?

    #path from the file
    (\s\(\))?  (\sat\s)?
    (?P<path>
     .*\.c
    )?
    #Number of the line
    :?
    (?P<lineno>
    [0-9]+
    )*
"""
)


_image_re = re.compile(
    r"""(?x)
    
    # address of image
    (?P<image_addr>
        0[xX][a-fA-F0-9]+
    )*

    # size of image
    \+
    (?P<image_size>
        0[xX][a-fA-F0-9]+
    )*

    # code ID
    \s
    (?P<code_id>
        [0-9A-Fa-f]+
    )*

    # other address of image?
    @
    (?:
        0[xX][0-9A-F-a-f]+
    )*

    #Code File
    (\s|\s\.\s\-\s)?
    (\.\s)?   
    (-\s)*
    (?P<code_file>
        [\/|.\/][\w|\S]+|\S+\.\S+|[a-zA-Z]*
    )?
"""
)


def code_id_to_debug_id(code_id):
    return str(uuid.UUID(bytes_le=binascii.unhexlify(code_id)[:16]))


def error(message):
    print("error: {}".format(message))
    sys.exit(1)


def get_frame(gdb_output):
    """Parses the output from gdb  """
    frame = Frame()
    temp = _frame_re.search(gdb_output)
    if temp is None:
        return

    frame.instruction_addr = temp.group("instruction_addr")
    frame.name_of_function = temp.group("name_of_function")
    frame.lineno = temp.group("lineno")
    if temp.group("path") is None:
        frame.path = "abs_path"
    else:
        frame.path = temp.group("path")
    return frame


def get_image(image_string):
    """Parses the output from eu-unstrip"""
    temp = _image_re.search(image_string)
    if temp is None:
        return None

    return Image(
        type="elf",
        image_addr=temp.group("image_addr"),
        image_size=int(temp.group("image_size"), 16),
        code_id=temp.group("code_id"),
        debug_id=code_id_to_debug_id(temp.group("code_id")),
        code_file=temp.group("code_file"),
    )


@click.command()
@click.argument("path_to_core")
@click.argument("path_to_executable")
@click.option("--sentry-dsn", required=False)
def main(path_to_core, path_to_executable, sentry_dsn):

    # Validate input Path
    if os.path.isfile(path_to_core) is not True:
        error("Wrong path to coredump")

    if os.path.isfile(path_to_executable) is not True:
        error("Wrong path to executable")

    image_list = []
    frame_list = []

    gdb_output = []
    eu_unstrip_output = []

    # execute gdb
    process = subprocess.Popen(
        ["gdb", "-c", path_to_core, "-e", path_to_executable],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
    )

    output = re.search(r"#0.*", str(process.communicate(input="bt")))
    try:
        gdb_output = output.group().split("#")
    except:
        error("gdb output error")

    # execute eu-unstrip
    process = subprocess.Popen(
        ["eu-unstrip", "-n", "--core", path_to_core, "-e", path_to_executable],
        stdout=subprocess.PIPE,
    )

    output = process.communicate()

    eu_unstrip_output = str(output[0]).split("\n")

    for x in range(2, len(gdb_output)):
        frame = get_frame(gdb_output[x])
        if frame is not None:
            frame_list.append(frame)

    for x in range(0, len(eu_unstrip_output) - 1):
        image = get_image(eu_unstrip_output[x])
        if image is not None:
            image_list.append(image)

    # build the json for sentry
    data = {
        "platform": "native",
        "exception": {
            "type": "Core",
            "handled": "false",
            "stacktrace": {"frames": [ob.to_json() for ob in frame_list]},
        },
        "debug_meta": {"images": [ob.to_json() for ob in image_list]},
    }

    sentry_sdk.init(sentry_dsn)
    sentry_sdk.capture_event(data)
    print("Core dump sent to sentry")


if __name__ == "__main__":
    main()
