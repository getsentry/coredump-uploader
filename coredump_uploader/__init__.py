import re
import sentry_sdk
import binascii
import uuid
import subprocess
import sys
import os
import click
import time
import datetime
import signal
import copy


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
        self.registers = {}

    def append_frame(self, frame=None):
        self.frames.append(frame)

    def ad_register(self, name, value):
        self.registers[name] = value

    def reverse_list(self):
        self.frames.reverse()

    def to_json(self):
        for i, frame in enumerate(self.frames):
            try:
                self.frames[i] = frame.to_json()
            except:
                continue
        return self.__dict__


class Thread:
    def __init__(self, id="", name=None, crashed=False, stacktrace=None):
        self.id = id
        self.name = name
        self.crashed = crashed
        self.stacktrace = stacktrace

    def get_stacktrace(self):
        return self.stacktrace

    def to_json(self):
        if self.stacktrace is not None and isinstance(self.stacktrace, Stacktrace):
            self.stacktrace = self.stacktrace.to_json()
        return self.__dict__


class CrashedThread:
    def __init__(self, id="", name=None, crashed=False):
        self.id = id
        self.name = name
        self.crashed = crashed

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

_thread_id_re = re.compile(
    r"(?i)(?P<thread_id>\d+) (\(thread 0x[0-9a-f]+ )?\((?P<thread_name>.*?)\)\)?"
)

_exit_signal_re = re.compile(r"(?i)terminated with signal (?P<type>[a-z0-9]+),")

_thread_re = re.compile(
    r"(?x)^Thread .*? (\n\n|.\(gdb\)\squit)", flags=re.DOTALL | re.MULTILINE
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

    if temp.group("function") not in (None, "??"):
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


def execute_gdb(gdb_path, path_to_core, path_to_executable, gdb_command):
    """creates a subprocess for gdb and returns the output from gdb"""

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

    output, errors = process.communicate(input=gdb_command)
    if errors:
        error(errors)

    output.decode("utf-8")

    return output


def get_all_threads(gdb_output):
    """Returns a list with all threads and backtraces"""

    thread_list = []
    counter_threads = 0
    stacktrace_temp = None

    crashed_thread_id = re.search(
        r"(?i)current thread is (?P<thread_id>\d+)", gdb_output,
    )
    if crashed_thread_id:
        crashed_thread_id = crashed_thread_id.group("thread_id")
    else:
        crashed_thread_id = "1"

    # Get the exit Signal from the gdb-output
    exit_signal = re.search(_exit_signal_re, gdb_output)
    if exit_signal:
        exit_signal = exit_signal.group("type")
    else:
        exit_signal = "Core"

    # Searches for threads in gdb_output
    for temp in re.finditer(_thread_re, gdb_output):
        thread_backtrace = str(temp.group())
        stacktrace = Stacktrace()

        # Gets the Thread ID
        thread_id = re.search(_thread_id_re, thread_backtrace,)
        if thread_id is None:
            continue
        else:
            thread_name = thread_id.group("thread_name")
            thread_id = thread_id.group("thread_id")

        # Gets each frame from the Thread
        for match in re.finditer(_frame_re, thread_backtrace):
            frame = get_frame(match)
            if frame is not None:
                stacktrace.append_frame(frame)

        stacktrace.reverse_list()

        crashed = thread_id == crashed_thread_id

        # Appends a Thread to the thread_list
        if crashed:
            thread_list.append(CrashedThread(thread_id, thread_name, crashed))
            stacktrace_temp = stacktrace
        else:
            thread_list.append(Thread(thread_id, thread_name, crashed, stacktrace))

        if not stacktrace_temp:
            stacktrace_temp = stacktrace

        counter_threads += 1

    thread_list.reverse()
    print("Threads found: " + str(counter_threads))
    return thread_list, exit_signal, stacktrace_temp, crashed_thread_id


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

    if all_threads:
        gdb_output = execute_gdb(
            gdb_path, path_to_core, path_to_executable, "thread apply all bt"
        )
        thread_list, exit_signal, stacktrace, crashed_thread_id = get_all_threads(
            gdb_output
        )

    else:
        stacktrace = Stacktrace()
        crashed_thread_id = None
        gdb_output = execute_gdb(gdb_path, path_to_core, path_to_executable, "bt")
        if not "#0" in gdb_output:
            error("gdb output error")

        # Get the exit Signal from the gdb-output
        exit_signal = re.search(_exit_signal_re, gdb_output)
        if exit_signal:
            exit_signal = exit_signal.group("type")
        else:
            exit_signal = "Core"

        # Searches for frames in the GDB-Output
        for match in re.finditer(_frame_re, gdb_output):
            frame = get_frame(match)
            if frame is not None:
                stacktrace.append_frame(frame)

        stacktrace.reverse_list()

    # Get registers from gdb
    gdb_output = execute_gdb(
        gdb_path, path_to_core, path_to_executable, "info registers"
    )

    for match in re.finditer(_register_re, gdb_output):
        if match is not None:
            stacktrace.ad_register(
                match.group("register_name"), match.group("register_value")
            )

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
        timestamp = stat.st_mtime
    except AttributeError:
        timestamp = None

    # Get signal Number from signal name
    try:
        temp = str(
            "-l" + re.match(r"SIG(?P<exit_signal>.*)", exit_signal).group("exit_signal")
        )
        exit_signal_number = subprocess.check_output(["kill", temp])
    except err:
        exit_signal_number = None

    # Make the image_list to json
    for i, image in enumerate(image_list):
        try:
            image_list[i] = image.to_json()
        except:
            continue

    # Gets the stacktrace from the thread_list
    if all_threads:
        for i, thread in enumerate(thread_list):
            thread_list[i] = thread.to_json()

    else:
        thread_list = None

    # Build the json for sentry
    sdk_name = "coredump.uploader.sdk"
    sdk_version = "0.0.1"

    data = {
        "timestamp": timestamp,
        "platform": "native",
        "exception": {
            "type": exit_signal,
            "thread_id": crashed_thread_id,
            "mechanism": {
                "type": "coredump",
                "handled": False,
                "synthetic": True,
                "meta": {
                    "signal": {
                        "number": int(exit_signal_number),
                        "code": None,
                        "name": exit_signal,
                    },
                },
            },
            "stacktrace": stacktrace.to_json(),
        },
        "debug_meta": {"images": image_list},
        "threads": {"values": thread_list},
        "sdk": {"name": sdk_name, "version": sdk_version,},
    }

    sentry_sdk.init(sentry_dsn, max_breadcrumbs=0)
    sentry_sdk.integrations.modules.ModulesIntegration = None
    event_id = sentry_sdk.capture_event(data)
    print("Core dump sent to sentry: %s" % (event_id,))


if __name__ == "__main__":
    main()
