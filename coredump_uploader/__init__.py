import re
import sentry_sdk
import binascii
import uuid
import subprocess
import sys
import os
import click
import time
import signal


class Frame:
    def __init__(
        self,
        instruction_addr=None,
        function=None,
        filename=None,
        lineno=None,
        package=None,
    ):
        self.instruction_addr = instruction_addr
        self.function = function
        self.filename = filename
        self.lineno = lineno
        self.package = package

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


class Stacktrace:
    def __init__(self):
        self.frames = []

    def append_frame(self, frame=None):
        self.frames.append(frame)

    def reverse_list(self):
        self.frames.reverse()

    def to_json(self):
        return self.__dict__


class Thread:
    def __init__(self, id="", name=None, crashed=None, stacktrace=None):
        self.id = id
        self.name = name
        self.crashed = crashed
        self.stacktrace = stacktrace

    def get_stacktrace(self):
        return self.stacktrace

    def to_json(self):
        return self.__dict__


_frame_re = re.compile(
    r"""(?xim)
    ^
    # frame number
    \#\d+\s+
    # instruction address (missing for first frame)
    (?:
        (?P<instruction_addr>0x[0-9a-f]+)
        \sin\s
    )?
    # function name (?? if unknown)
    (?P<function>.*)
    \s
    # arguments, ignored
    \([^)]*\)
    
    \s*
    (?:
        # package name, without debug info
        from\s
        (?P<package>[^ ]+)
    |
        # file name and line number
        at\s
        (?P<filename>[^ ]+)
        :
        (?P<lineno>\d+)
    )?
    $
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
    \.?
    (?P<code_file>
        [\/|\/][\w|\S]+|\S+\.\S+|[a-zA-Z]*
    )?
    """
)

_register_re = re.compile(
    r"""(?xi)
    
    # name of the register 
    (?P<register_name>[0-9a-z]+)
    \s*

    # value of the register
    (?P<register_value>0x[0-9a-f]+)
    """
)

def code_id_to_debug_id(code_id):
    return str(uuid.UUID(bytes_le=binascii.unhexlify(code_id)[:16]))


def error(message):
    print("error: {}".format(message))
    sys.exit(1)


def get_frame(temp):
    """Returns a Frame"""
    frame = Frame()
    if temp.group("instruction_addr") is not None:
        frame.instruction_addr = temp.group("instruction_addr")

    if temp.group("function") is not None:
        frame.function = temp.group("function")

    if temp.group("lineno") is not None:
        frame.lineno = int(temp.group("lineno"))

    if temp.group("filename") is not None:
        frame.filename = temp.group("filename")

    if temp.group("package") is not None:
        frame.package = temp.group("package")

    return frame


def get_image(temp):
    """Returns an Image"""
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


def execute_gdb(gdb_path, path_to_core, path_to_executable):
    """creates a subprocess for gdb and returns it"""

    if gdb_path is None:
        process = subprocess.Popen(
            ["gdb", "-c", path_to_core, path_to_executable],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
    else:
        try:
            process = subprocess.Popen(
                [gdb_path, "gdb", "-c", path_to_core, path_to_executable],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
        except OSError as err:
            error(err)

    return process


def get_all_threads(process):
    """Returns a list with all threads and backtraces"""

    thread_list = []
    counter_threads = 0

    output, errors = process.communicate(input="thread apply all bt")
    if errors:
        error(errors)

    gdb_output = output.decode("utf-8")

    # splits gdb output to get each Thread
    try:
        gdb_output = output.split("Thread")
    except:
        error("gdb output error")

    crashed_thread_id = re.search(
        r"(?xi)\[Current\s thread\s is\s [0-9a-z]*\s\([a-z]*\s? (?P<thread_id>[a-z0-9]+) \)]",
        gdb_output[0],
    )
    # Get the exit Signal from the gdb-output
    try:
        exit_signal = re.search(
            r"(?i)terminated with signal (?P<type>[a-z0-9]+),", gdb_output[0]
        ).group("type")
    except:
        exit_signal = "Core"

    del gdb_output[0]
    gdb_output.reverse()

    for thread_backtrace in gdb_output:
        stacktrace = Stacktrace()

        # gets the Thread ID
        thread_id = re.search(
            r"(?xi) [0-9a-z]*\s\([a-z]*\s? (?P<thread_id>[a-fA-F0-9]+)",
            thread_backtrace,
        )

        # gets each frame from the Thread
        for match in re.finditer(_frame_re, thread_backtrace):
            frame = get_frame(match)
            if frame is not None:
                stacktrace.append_frame(frame.to_json())

        stacktrace.reverse_list()

        if thread_id.group("thread_id") == crashed_thread_id.group("thread_id"):
            crashed = True
        else:
            crashed = False

        # appends a Thread to the thread_list
        thread_list.append(
            Thread(thread_id.group("thread_id"), None, crashed, stacktrace.to_json())
        )
        counter_threads += 1

    print("Threads found: " + str(counter_threads))
    return thread_list, exit_signal


@click.command()
@click.argument("path_to_core")
@click.argument("path_to_executable")
@click.option("--sentry-dsn", required=False, help="Your sentry dsn")
@click.option("--gdb-path", required=False, help="Path to gdb")
@click.option("--elfutils-path", required=False, help="Path to elfutils")
@click.option(
    "--all-threads", is_flag=True, help="Sends the backtrace from all threads to sentry"
)
def main(
    path_to_core, path_to_executable, sentry_dsn, gdb_path, elfutils_path, all_threads
):
    # Validate input Path
    if os.path.isfile(path_to_core) is not True:
        error("Wrong path to coredump")

    if os.path.isfile(path_to_executable) is not True:
        error("Wrong path to executable")

    if gdb_path is not None and os.path.exists(gdb_path) is not True:
        error("Wrong path for gdb")

    if elfutils_path is not None and os.path.exists(elfutils_path) is not True:
        error("Wrong path for elfutils")

    # execute gdb
    process = execute_gdb(gdb_path, path_to_core, path_to_executable)

    if all_threads:
        thread_list, exit_signal = get_all_threads(process)

    else:
        stacktrace = Stacktrace()

        output, errors = process.communicate(input="bt")
        if errors:
            error(errors)

        gdb_output = output.decode("utf-8")
        if not "#0" in gdb_output:
            error("gdb output error")

        # Get the exit Signal from the gdb-output
        try:
            exit_signal = re.search(
                r"(?i)terminated with signal (?P<type>[a-z0-9]+),", gdb_output
            ).group("type")
        except:
            exit_signal = "Core"

        # Searches for frames in the GDB-Output
        for match in re.finditer(_frame_re, gdb_output):
            frame = get_frame(match)
            if frame is not None:
                stacktrace.append_frame(frame.to_json())

        stacktrace.reverse_list()

    image_list = []

    # execute eu-unstrip
    if elfutils_path is None:
        process = subprocess.Popen(
            ["eu-unstrip", "-n", "--core", path_to_core, "-e", path_to_executable],
            stdout=subprocess.PIPE,
        )
    else:
        try:
            process = subprocess.Popen(
                [
                    elfutils_path,
                    "eu-unstrip",
                    "-n",
                    "--core",
                    path_to_core,
                    "-e",
                    path_to_executable,
                ],
                stdout=subprocess.PIPE,
            )
        except OSError as err:
            error(err)

    output, errors = process.communicate()
    if errors:
        error(errors)

    eu_unstrip_output = output.decode("utf-8")

    # Searches for images in the Eu-Unstrip Output
    for match in re.finditer(_image_re, eu_unstrip_output):
        image = get_image(match)
        if image is not None:
            image_list.append(image)
    
    # Get timestamp
    stat = os.stat(path_to_core)
    try:
        timestamp = stat.st_birthtime
    except AttributeError:
        timestamp = stat.st_mtime

    # build the json for sentry
    if all_threads:
        for temp in thread_list:
            if temp.crashed:
                stacktrace = temp.get_stacktrace()
                break

        data = {
            "platform": "native",
            "exception": {
                "type": "Crash",
                "mechanism": {"type": "coredump", "handled": False, "synthetic": True},
                "stacktrace": stacktrace,
            },
            "debug_meta": {"images": [ob.to_json() for ob in image_list]},
            "threads": {"values": [ob.to_json() for ob in thread_list]},
        }
    else:
        data = {
            "platform": "native",
            "exception": {
                "type": "Crash",
                "mechanism": {
                    "type": "coredump",
                    "handled": False,
                    "synthetic": True,
                    "signal": {"number": None, "code": None, "name": exit_signal,},
                },
                "stacktrace": stacktrace.to_json(),
            },
            "debug_meta": {"images": [ob.to_json() for ob in image_list]},
        }

    sentry_sdk.init(sentry_dsn)
    event_id = sentry_sdk.capture_event(data)
    print("Core dump sent to sentry: %s" % (event_id,))


if __name__ == "__main__":
    main()
