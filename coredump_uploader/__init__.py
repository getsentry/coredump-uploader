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
import logging
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler


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
        arch="",
    ):
        self.type = type
        self.image_addr = image_addr
        self.image_size = image_size
        self.debug_id = debug_id
        self.code_id = code_id
        self.code_file = code_file
        self.arch = arch

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
    [^\#] (?P<register_name>[0-9a-z]+)
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


def get_threads(gdb_output):
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


def get_stacktrace(gdb_output):
    """Returns the stacktrace and the exit signal """
    if not "#0" in gdb_output:
        error("gdb output error")
    stacktrace = Stacktrace()
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
    return stacktrace, exit_signal


def error(message):
    print("error: {}".format(message))
    sys.exit(1)


def get_timestamp(path_to_core):
    """Returns the timestamp from a file"""
    stat = os.stat(path_to_core)
    try:
        timestamp = stat.st_mtime
    except AttributeError:
        timestamp = None

    return timestamp


def signal_name_to_signal_number(signal_name):
    """Returns the Unix signal number from the signal name"""
    try:
        temp = str(
            "-l" + re.match(r"SIG(?P<exit_signal>.*)", signal_name).group("exit_signal")
        )
        exit_signal_number = subprocess.check_output(["kill", temp])
    except AttributeError:
        exit_signal_number = None

    return exit_signal_number


class CoredumpHandler(RegexMatchingEventHandler):
    def __init__(self, uploader, *args, **kwargs):
        super(CoredumpHandler, self).__init__(*args, **kwargs)
        self.uploader = uploader

    def on_created(self, event):
        """Uploads an event to sentry"""
        self.uploader.upload(event.src_path)


class CoredumpUploader(object):
    def __init__(
        self, path_to_executable, sentry_dsn, gdb_path, elfutils_path, all_threads
    ):
        if not os.path.isfile(path_to_executable):
            error("Wrong path to executable")

        if gdb_path is not None and os.path.exists(gdb_path) is not True:
            error("Wrong path for gdb")
        if gdb_path is None:
            gdb_path = "gdb"

        if elfutils_path is not None and os.path.exists(elfutils_path) is not True:
            error("Wrong path for elfutils")
        if elfutils_path is None:
            elfutils_path = "eu-unstrip"

        self.path_to_executable = path_to_executable
        self.sentry_dsn = sentry_dsn
        self.gdb_path = gdb_path
        self.elfutils_path = elfutils_path
        self.all_threads = all_threads

    def execute_gdb(self, path_to_core, gdb_command):
        """creates a subprocess for gdb and returns the output from gdb"""

        try:
            process = subprocess.Popen(
                [self.gdb_path, "-c", path_to_core, self.path_to_executable],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
        except OSError as err:
            error(err)

        output, errors = process.communicate(input=gdb_command)
        if errors:
            error(errors)

        return output.decode("utf-8")

    def execute_elfutils(self, path_to_core):
        """Executes eu-unstrip & returns the output"""
        try:
            process = subprocess.Popen(
                [
                    self.elfutils_path,
                    "-n",
                    "--core",
                    path_to_core,
                    "-e",
                    self.path_to_executable,
                ],
                stdout=subprocess.PIPE,
            )
        except OSError as err:
            error(err)

        output, errors = process.communicate()
        if errors:
            error(errors)

        return output.decode("utf-8")

    def get_registers(self, path_to_core, stacktrace):
        """Returns the stacktrace with the registers, the gdb-version and the message."""
        gdb_output = self.execute_gdb(path_to_core, "info registers")
        gdb_version = re.match(r"GNU gdb \(.*?\) (?P<gdb_version>.*)", gdb_output)
        if gdb_version:
            gdb_version = gdb_version.group("gdb_version")

        message = re.search(r"(?P<message>Core was generated .*\n.*)", gdb_output)
        if message:
            message = message.group("message")

        for match in re.finditer(_register_re, gdb_output):
            if match is not None:
                stacktrace.ad_register(
                    match.group("register_name"), match.group("register_value")
                )
        return (
            stacktrace,
            gdb_version,
            message,
        )

    def upload(self, path_to_core):
        """Uploads the event to sentry"""
        # Validate input Path
        if os.path.isfile(path_to_core) is not True:
            error("Wrong path to coredump")

        if self.all_threads:
            gdb_output = self.execute_gdb(path_to_core, "thread apply all bt")
            (thread_list, exit_signal, stacktrace, crashed_thread_id,) = get_threads(
                gdb_output
            )
        else:
            gdb_output = self.execute_gdb(path_to_core, "bt")
            stacktrace, exit_signal = get_stacktrace(gdb_output)
            thread_list = None
            crashed_thread_id = None

        # gets the registers, the gdb-version and the message
        stacktrace, gdb_version, message = self.get_registers(path_to_core, stacktrace)

        image_list = []

        # Searches for images in the Eu-Unstrip Output
        eu_unstrip_output = self.execute_elfutils(path_to_core)
        for match in re.finditer(_image_re, eu_unstrip_output):
            image = get_image(match)
            if image is not None:
                image_list.append(image)

        # Get timestamp
        timestamp = get_timestamp(path_to_core)

        # Get signal Number from signal name
        exit_signal_number = signal_name_to_signal_number(exit_signal)

        # Get elfutils version
        process = subprocess.Popen(
            [self.elfutils_path, "--version"],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        elfutils_version, err = process.communicate()
        if err:
            print(err)

        if elfutils_version:
            elfutils_version = re.search(
                r"eu-unstrip \(elfutils\) (?P<elfutils_version>.*)", elfutils_version
            ).group("elfutils_version")

        # Get OS context
        process = subprocess.Popen(
            ["uname", "-s", "-r"], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
        )
        os_context, err = process.communicate()
        os_context = re.search(r"(?P<name>.*?) (?P<version>.*)", os_context)
        if os_context:
            os_name = os_context.group("name")
            os_version = os_context.group("version")
        else:
            os_name = None
            os_version = None
        process = subprocess.Popen(
            ["uname", "-a"], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
        )
        os_raw_context, err = process.communicate()

        # Get App Contex
        process = subprocess.Popen(
            ["file", path_to_core], stdout=subprocess.PIPE, stdin=subprocess.PIPE,
        )
        app_context, err = process.communicate()
        app_context = re.search(
            r"from '.*?( (?P<args>.*))?', .* execfn: '.*\/(?P<app_name>.*?)', platform: '(?P<arch>.*?)'",
            app_context,
        )
        if app_context:
            args = app_context.group("args")
            app_name = app_context.group("app_name")
            arch = app_context.group("arch")

        # Make a json from the Thread_list
        if thread_list:
            for i, thread in enumerate(thread_list):
                thread_list[i] = thread.to_json()

        # Make the image_list to json
        for i, image in enumerate(image_list):
            try:
                if arch:
                    image_list[i].arch = arch
                image_list[i] = image.to_json()
            except:
                continue

        # Get value, exception from message
        message = re.search(
            r"(?P<message>.*)\n(?P<value>.*?, (?P<type>.*?)\.)", message
        )
        if message:
            value_exception = message.group("value")
            type_exception = message.group("type")
            message = message.group("message")
        if type_exception is None:
            type_exception = exit_signal

        # Build the json for sentry
        sentry_sdk.integrations.modules.ModulesIntegration = None
        sentry_sdk.integrations.argv.ArgvIntegration = None
        event_id = uuid.uuid4().hex
        sdk_name = "coredump.uploader.sdk"
        sdk_version = "0.0.1"
        data = {
            "event_id": event_id,
            "timestamp": timestamp,
            "platform": "native",
            "message": {"message": message,},
            "exception": {
                "value": value_exception,
                "type": type_exception,
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
            "contexts": {
                "gdb": {"type": "runtime", "name": "gdb", "version": gdb_version,},
                "elfutils": {
                    "type": "runtime",
                    "name": "elfutils",
                    "version": elfutils_version,
                },
                "os": {
                    "name": os_name,
                    "version": os_version,
                    "raw_description": os_raw_context,
                },
                "runtime": None,
                "app": {"app_name": app_name, "argv": args,},
            },
            "debug_meta": {"images": image_list},
            "threads": {"values": thread_list},
            "sdk": {"name": sdk_name, "version": sdk_version,},
        }
        event_id = sentry_sdk.capture_event(data)
        print("Core dump sent to sentry: %s" % (event_id))


@click.group()
@click.argument("path_to_executable")
@click.option("--sentry-dsn", required=False, help="Your sentry dsn")
@click.option("--gdb-path", required=False, help="Path to gdb")
@click.option("--elfutils-path", required=False, help="Path to elfutils")
@click.option(
    "--all-threads", is_flag=True, help="Sends the backtrace from all threads to sentry"
)
@click.pass_context
def cli(context, path_to_executable, sentry_dsn, gdb_path, elfutils_path, all_threads):
    """Initialize Sentry-dsn and Coredump-uploader"""
    sentry_sdk.init(sentry_dsn, max_breadcrumbs=0)
    uploader = CoredumpUploader(
        path_to_executable, sentry_dsn, gdb_path, elfutils_path, all_threads
    )

    context.ensure_object(dict)
    context.obj["uploader"] = uploader


@cli.command()
@click.argument("path_to_core")
@click.pass_context
def upload(context, path_to_core):
    """Uploads the coredump"""
    uploader = context.obj["uploader"]
    uploader.upload(path_to_core)


@cli.command()
@click.argument("watch_dir")
@click.pass_context
def watch(context, watch_dir):
    """Starts the Observer and creates the CoredumpHandler"""
    uploader = context.obj["uploader"]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print("Starting watchdog...")

    regexes = [".*core.*"]
    handler = CoredumpHandler(uploader, ignore_directories=True, regexes=regexes)

    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=False)
    observer.start()

    print("Watchdog started, looking for new coredumps in : %s" % watch_dir)
    print("Press ctrl+c to stop\n")

    try:
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        observer.stop()
        observer.join()
        print("")


if __name__ == "__main__":
    cli()
