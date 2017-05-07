import struct
import sys


class ByteStream(object):
    """
    Class to read from little-endian formatted bytestream
    """

    LITTLE_ENDIAN_INT_FORMAT = "<i"
    LITTLE_ENDIAN_SHORT_FORMAT = "<h"
    LITTLE_ENDIAN_LONG_LONG_FORMAT = "<Q"

    def __init__(self, path):
        self._path = path
        self._file = open(self._path, 'r+b')
        self._look_ahead = None
        self._look_ahead_pos = None
        self._look_ahead_index = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._file.close()
        return False

    def read_byte(self):
        if sys.version_info >= (3,):
            return self._file.read(1)[0]
        else:
            return ord(self._file.read(1)[0])

    def read_short(self):
        return struct.unpack(ByteStream.LITTLE_ENDIAN_SHORT_FORMAT, self._file.read(2))[0]

    def read_int(self):
        return struct.unpack(ByteStream.LITTLE_ENDIAN_INT_FORMAT, self._file.read(4))[0]

    def read_ints(self, count):
        return struct.unpack("<%di" % count, self._file.read(count * 4))

    def read_leb128(self):
        result = 0
        shift = 0
        while True:
            current = self.read_byte()
            result |= ((current & 0x7f) << shift)
            if (current & 0x80) == 0:
                break
            shift += 7
            if shift >= 35:
                raise Exception("LEB128 sequence invalid")
        return result

    def read_bytes(self, byte_count):
        return bytes(self._file.read(byte_count))

    def read_string(self):
        pos = self._file.tell()
        result = ""
        byte_data = self._file.read(128)
        while byte_data:
            fmt = "<%ds" % len(byte_data)
            delta = struct.unpack(fmt, byte_data)[0].decode('latin-1').split(chr(0))[0]
            result += delta
            if len(byte_data) == 128 and len(delta) == 128:
                byte_data = self._file.read(128)
            else:
                byte_data = None
        pos += len(result)
        self._file.seek(pos)
        return result

    def tell(self):
        return self._file.tell()

    def seek(self, pos):
        return self._file.seek(pos)

    def read(self, count):
        return self._file.read(count)

    def parse_items(self, count, offset, clazz):
        """
        :param count: number of iteams of type clazz to parse
        :param offset: osffset within file to start parsing, or None to start at current location
        :param clazz: `DexParser.Item` subclass to parse into
        :return: collection of requested number of clazz instances parsed from bytestream
        """
        if count == 0:
            return []
        if offset is not None:
            self._file.seek(offset)
        return clazz.get(self, count)

    def parse_descriptor(self, string_id):
        self._file.seek(string_id.data_offset)
        # read past unused:
        self.read_leb128()
        return self.read_string()

    def parse_method_name(self, method_id):
        string_id = method_id._string_ids[method_id.name_index]
        return self.parse_descriptor(string_id)
