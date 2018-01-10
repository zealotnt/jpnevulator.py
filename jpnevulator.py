#!/usr/bin/env python

"""
jpnevulator.py

A Python version of jpnevulator.

If you don't need jpnevulator CLI compatiblitity,
you could also use https://git.jim.sh/jim/terminal.git .

Usage of the original jpnevulator:

jpnevulator [--version] [--help] [--checksum] [--crc16=poly]
  [--crc8=poly] [--fuck-up] [--file=file] [--no-send]
  [--delay-line=microseconds] [--delay-byte=microseconds]
  [--print] [--size=size] [--tty=tty] [--pty [=alias]] [--width] [--pass]
  [--read] [--write] [--timing-print] [--timing-delta=microseconds]
  [--ascii] [--alias-separator=separator] [--byte-count]
  [--control] [--control-poll=microseconds] [--count=bytes] <file>

"""

import argparse
import sys
import time
import textwrap
from datetime import datetime as dt
import colorama
import serial
import os
import re

try:
    clock = time.perf_counter
except AttributeError:
    clock = time.time

class MultiArg(argparse.Action):
    """
    An action adding the supplied values of multiple
    statements of the same optional argument to a list.

    inspired by http://stackoverflow.com/a/12461237/183995
    """
    def __call__(self, parser, namespace, values, option_strings=None):
        dest = getattr(namespace, self.dest, None) 
        #print(self.dest, dest, self.default, values, option_strings)
        if(not hasattr(dest,'append') or dest == self.default):
            dest = []
            setattr(namespace, self.dest, dest)
            parser.set_defaults(**{self.dest:None}) 
        dest.append(values)

def port_def(string):
    if ':' in string:
        port, _, alias = string.partition(':')
    else:
        port, alias = string, None
    if '@' in port:
        port, _, baudrate = port.partition('@')
        try:
            baudrate = int(baudrate)
        except ValueError:
            raise argparse.ArgumentTypeError('the specified baudrate is not an integer')
    else:
        baudrate = None
    return {'port': port, 'alias': alias, 'baudrate': baudrate}

def hex_format(chunk):
    try:
        return ' '.join('{:02X}'.format(byte) for byte in chunk)
    except ValueError:
        return ' '.join('{:02X}'.format(ord(byte)) for byte in chunk)

def ascii_format(chunk):
    printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    try:
        chars = [chr(i) for i in chunk]
        return ''.join([char if char in printable else '.' for char in chars])
    except TypeError:
        chars = chunk
        return ''.join([char if char in printable else '.' for char in chars])

def print_err(text):
    print (colorama.Style.BRIGHT + colorama.Fore.RED + text + colorama.Style.RESET_ALL)

def print_ok(text):
    print (colorama.Style.BRIGHT + colorama.Fore.GREEN + text + colorama.Style.RESET_ALL)

# If python 2, type(data) should be string
# If python 3, type(data) should be bytes
def dump_hex(data, desc_str="", token=":", prefix="", wrap=0, preFormat=""):
    """
    data: hex data to be dump
    desc_str: description string, will be print first
    token: the mark to seperated between bytes
    prefix: prefix of bytes
    wrap: number of bytes to be printed before create a new line
    """
    global gStr
    gStr = ""
    def concat_str(text):
        global gStr
        gStr += text
    def write_and_concat_str(text):
        concat_str(text)
        sys.stdout.write(text)

    varType = ""
    varArray = ""
    postfix = ""
    if preFormat == "C" or preFormat == "c":
        token = ", "
        prefix = "0x"
        wrap = 8
        varType = "uint8_t"
        varArray = "[]"
        postfix = "\r\n\t};\r\n\r\n"
    elif preFormat == "raw":
        token = " "
        prefix = ""
        wrap = 0
        desc_str = '"%s":\r\n' % (desc_str)
        postfix = "\r\n\r\n"
    else:
        postfix = "\r\n\t\t}\r\n\r\n"

    # print desc_str + binascii.hexlify(data)
    if wrap == 0:
        to_write = desc_str + token.join(prefix+"{:02x}".format(ord(c)) for c in data) + "\r\n"
        write_and_concat_str(to_write)
    else:
        # [Ref](http://stackoverflow.com/questions/734368/type-checking-of-arguments-python)
        if isinstance(data, int):
            data = bigIntToBytes(data)

        count = 0

        write_and_concat_str("%s %s%s = {\r\n\t\t" % (varType, desc_str, varArray))
        for c in data:
            if (count % wrap == 0) and (count != 0) and (wrap != 0):
                write_and_concat_str("\r\n\t\t")
            if pythonVer() == 2:
                to_write = prefix + "{:02x}".format(ord(c)) + token
            else:
                to_write = prefix + "{:02x}".format(c) + token
            write_and_concat_str(to_write)
            count += 1

        write_and_concat_str(postfix)
        sys.stdout.flush()
    ret = gStr
    del gStr
    return ret
# Register another name for the dump_hex function
hex_dump = dump_hex

def get_fullpath(file_dir, file_name):
    if file_dir == "":
        return file_name
    return file_dir + os.sep + file_name

def parse_scpcmd_file(filename):
    """
    :param cmds_file:
    :param file_dir:
    :param :
    :return:
    """

    print 'Open file: ' + filename
    cmds_file = open(filename, 'r')
    file_dir = os.path.dirname(filename)

    packet_list = []

    # Get number of packets to send
    for line in cmds_file:
        file_name = line.strip()
        s_m = re.search('(\w+[_-]*\w+)\.(\d+)\.(\w+[_-]*\w+)\.((\w+[_-]*)*)\.\w+', file_name)
        if s_m is not None:
            id = s_m.group(2)
            cmd = s_m.group(4)
            way_str = s_m.group(3)
        else:
            print("error: wrong filename: " + file_name)
            raise Exception()

        if way_str == 'bl':
            way = False
        elif way_str == 'host':
            way = True
        else:
            print("error: wrong filename: " + file_name)
            raise Exception()

        packet_data = open(get_fullpath(file_dir, file_name), 'rb').read()
        packet = {
            "data": packet_data,
            "type": "CMD" if way_str == "host" else "RSP",
            "is_check": False,
            "is_ignore": True if cmd == "hello_reply" else False,
        }
        packet_list.append(packet)

    cmds_file.close()

    return packet_list

def process_scp_data(data, firmware_packets):
    org_data = data
    marked_firmware_packets = firmware_packets

    for idx, packet in enumerate(firmware_packets):
        if packet["is_check"] == True:
            continue
        if packet["data"] == data:
            marked_firmware_packets[idx]["is_check"] = True
            print_ok ("=> Data match %d" % (idx + 1))
            return marked_firmware_packets
        elif packet["data"] == data[:len(packet["data"])]:
            data = data[len(packet["data"]):]
            marked_firmware_packets[idx]["is_check"] = True
            print_ok ("=> Data match %d (cont)" % (idx + 1))
            continue
        elif packet["is_ignore"] is True:
            marked_firmware_packets[idx]["is_check"] = True
            print_ok ("=> Ignore packet %d" % (idx + 1))
            return marked_firmware_packets
        elif data == "\x00":
            dump_hex(org_data,       "Get   :")
            dump_hex(packet["data"], "Should:")
            print_err ("=> Wierd 00 byte at the end !!!")
            return firmware_packets
        else:
            if firmware_packets[0]["data"] in data[:len(firmware_packets[0]["data"])]:
                print_ok ("=> Ignore host_connection_request_packet")
                data = data[len(firmware_packets[0]["data"]):]
                if packet["data"] == data:
                    marked_firmware_packets[idx]["is_check"] = True
                    print_ok ("=> Data match %d" % (idx + 1))
                    return marked_firmware_packets
                elif packet["data"] == data[:len(packet["data"])]:
                    data = data[len(packet["data"]):]
                    marked_firmware_packets[idx]["is_check"] = True
                    print_ok ("=> Data match %d (cont)" % (idx + 1))
                    continue
                continue
            dump_hex(org_data,       "Get   :")
            dump_hex(packet["data"], "Should:")
            print_err ("=> Data not match !!!")
            return firmware_packets
    return marked_firmware_packets

def main():
    colorama.init()
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[1])
    parser.add_argument('-r', '--read', action='store_true', help='Put the program in read mode. This way you read the data from the given serial device(s) and write it to the file given or stdout if none given. See the read  section for more read specific .')
    parser.add_argument('-t', '--tty', type=port_def, dest='ttys', action=MultiArg, metavar='NAME@BAUDRATE:ALIAS', help="The serial device to read from. Use multiple times to read from more than one serial device(s). For handy reference you can also separate an alias from the tty name with a collon ':'. If an alias is given it will be used as the name of the serial device.")
    parser.add_argument('-e', '--timing-delta', type=int, metavar='MICROSECONDS', default=100000, help='The timing delta is the amount of microseconds between two bytes that the latter is considered to be part of a new package. The default is 100 miliseconds. Use this option in conjunction with the --timing-print option.')
    parser.add_argument('-g', '--timing-print', action='store_true', help='Print a line of timing information before every continues stream of bytes. When multiple serial devices are given also print the name or alias of the device where the data is coming from.')
    parser.add_argument('-a', '--ascii', action='store_true', help="Besides the hexadecimal output also display an extra column with the data in the ASCII representation. Non printable characters are displayed as a dot '.'. The ASCII data is displayed after the hexadecimal data.")
    parser.add_argument('-u', '--baudrate', type=int, default=9600, help='The baudrate to open the serial port at.')
    parser.add_argument('-i', '--width', type=int, default=16, help='The number of bytes to display on one line. The default is 16.')
    parser.add_argument('-v', '--version', action='store_true', help='Output the version information, a small GPL notice and exit.')
    parser.add_argument('-f', '--file-path', type=str, help='Firmware folder path.')
    args = parser.parse_args()

    if args.version:
        print(textwrap.dedent("""
        jpnevulator.py version 2.1.3
        Copyright (C) 2015 Philipp Klaus <philipp.l.klaus@web.de>
        This is free software.  You may redistribute copies of it under the terms of
        the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.
        There is NO WARRANTY, to the extent permitted by law.
        """))
        sys.exit(0)

    if not args.ttys:
        parser.error('please provide at least one --tty')

    num = 0
    ttys = args.ttys
    for tty in ttys:
        if not tty['baudrate']: tty['baudrate'] = args.baudrate
        if not tty['alias']: tty['alias'] = 'Port' + str(num)
        tty['buffer'] = b''
        tty['ser'] = serial.Serial(tty['port'], baudrate=tty['baudrate'], timeout=0)
        tty['last_byte'] = clock()
        num += 1
    tty_colors = {
        "0": colorama.Back.BLUE,
        "1": colorama.Back.YELLOW,
    }

    firmware_packets = []
    if args.file_path is not None:
        print_ok ("There is firmware")
        firmware_packets = parse_scpcmd_file(args.file_path)
        # for idx, packet in enumerate(firmware_packets):
        #     print "%3d: %s %d" % (idx, firmware_packets["type"], len(firmware_packets["data"]))

    try:
        while True:
            for tty in ttys:
                new_data = tty['ser'].read()
                if len(new_data) > 0:
                    tty['buffer'] += new_data
                    tty['last_byte'] = clock()
            for idx, tty in enumerate(ttys):
                if tty['buffer'] and (clock() - tty['last_byte']) > args.timing_delta/1E6:
                    tty['org_buffer'] = tty['buffer']
                    line = colorama.Style.BRIGHT + tty_colors["%d" % idx] + '{0}: {1}'.format(dt.now().isoformat(' '), tty['alias'])
                    line += colorama.Style.RESET_ALL + '\n'
                    sys.stdout.write(line)
                    while tty['buffer']:
                        if len(tty['buffer']) > 1024:
                            tty['buffer'] = ""
                            print("Data too long, skip printing")
                            break
                        chunk = tty['buffer'][:args.width]
                        tty['buffer'] = tty['buffer'][args.width:]
                        fmt = "{{hex:{0}s}}".format(args.width*3)
                        line = fmt.format(hex=hex_format(chunk))
                        if args.ascii:
                            fmt = "{{ascii:{0}s}}".format(args.width)
                            line += ' ' + fmt.format(ascii=ascii_format(chunk))
                        line = line.strip()
                        line += '\n'
                        sys.stdout.write(line)
                    sys.stdout.flush()
                    firmware_packets = process_scp_data(tty['org_buffer'], firmware_packets)

    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == "__main__": main()
