import struct
import sys
from functools import lru_cache


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

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._file.close()
        return False

    def read_byte(self):
        return self._file.read(1)[0]

    def read_short(self):
        return struct.unpack(ByteStream.LITTLE_ENDIAN_SHORT_FORMAT, self._file.read(2))[0]

    def read_int(self):
        return struct.unpack(ByteStream.LITTLE_ENDIAN_INT_FORMAT, self._file.read(4))[0]

    def read_unsigned_long_long(self):
        return struct.unpack(ByteStream.LITTLE_ENDIAN_LONG_LONG_FORMAT, self._file.read(8))[0]

    def read_leb128(self):
        result = 0
        count = 0
        while True:
            current = self._file.read(1)[0]
            result |= ((current & 0x7f) << count*7)
            if (current & 0x80) != 0x80 or count >= 5:
                break
        return result

    def read_bytes(self, byte_count):
        return self._file.read(byte_count)

    def read_string(self):
        pos = self._file.tell()
        result = ""
        byte_data = self._file.read(128)
        while byte_data:
            fmt = "<%ds" % len(byte_data)
            delta = struct.unpack(fmt, byte_data)[0].decode('utf-8')
            delta = delta.split(chr(0))[0]
            result += delta
            if len(byte_data) == 128 and len(delta) == 128:
                byte_data = self._file.read(128)
            else:
                byte_data = None
        pos += len(result)
        self._file.seek(pos)
        return result

    @lru_cache(maxsize=None)
    def parse_items(self, count, offset, clazz):
        if count == 0:
            return []
        if count is None:
            count = self.read_int()
        pos = self._file.tell()
        try:
            if offset is not None:
                self._file.seek(offset)
            return [clazz(self) for _ in range(count)]
        finally:
            self._file.seek(pos)

    @lru_cache(maxsize=None)
    def parse_descriptor(self, type_id, string_id):
        pos = self._file.tell()
        try:
            self._file.seek(string_id._data_offset)
            # read past unused:
            self.read_leb128()
            return self.read_string()

        finally:
            self._file.seek(pos)

    @lru_cache(maxsize=None)
    def parse_method_name(self, method_id):
        string_id = method_id._string_ids[method_id._name_index]
        self._file.seek(string_id._string_data_offset)
        self.read_leb128()  # read unused data
        return self.read_string()
