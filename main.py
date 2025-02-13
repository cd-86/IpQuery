import struct

class IpQueryQQWry:
    def __init__(self, file_path):
        with open(file_path, 'rb') as f:
            self.data = f.read()
        self.index_head = self._read_uint32(0)
        self.index_tail = self._read_uint32(4)

    def find_info(self, ip):
        ip_parts = list(map(int, ip.split('.')))
        nip = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        head, tail = self.index_head, self.index_tail

        while tail > head:
            mid = ((tail - head) // 7) // 2
            cur = head + (1 if mid == 0 else mid) * 7
            ip_min = self._read_uint32(cur)
            pos = self._read_uint24(cur + 4)
            ip_max = self._read_uint32(pos)

            if nip < ip_min:
                tail = cur
            elif nip > ip_max:
                head = cur
            else:
                pos += 4
                mode = self.data[pos]
                if mode == 0x01:
                    main_offset = self._read_uint24(pos + 1)
                    if self.data[main_offset] == 0x02:
                        info0, info1 = self._read_infos(main_offset, pos + 8)
                        desp = self._read_area(main_offset + 4)
                    else:
                        info0, info1 = self._read_infos(main_offset)
                        desp = self._read_area(main_offset + len(info0) + 1)
                elif mode == 0x02:
                    main_offset = self._read_uint24(pos + 1)
                    info0, info1 = self._read_infos(main_offset, pos + 4)
                    desp = ""
                else:
                    info0, info1 = self._read_infos(pos)
                    desp = self._read_area(pos + len(info0) + 1)
                return info0, info1, desp

        return "", "", ""

    def _read_infos(self, main_pos, sub_pos=0):
        main_info = self._read_string(main_pos)
        sub_pos = sub_pos or (main_pos + len(main_info))
        sub_info = self._read_string(sub_pos)
        return main_info, sub_info

    def _read_area(self, area_pos):
        mode = self.data[area_pos]
        if mode in (0x01, 0x02):
            area_pos = self._read_uint24(area_pos + 1)
            return "" if area_pos == 0 else self._read_string(area_pos)
        return self._read_string(area_pos)

    def _read_uint24(self, pos):
        return struct.unpack_from('<I', self.data[pos:pos + 3] + b'\x00')[0]

    def _read_uint32(self, pos):
        return struct.unpack_from('<I', self.data, pos)[0]

    def _read_string(self, pos):
        if self.data[pos] in (0x01, 0x02):
            pos = self._read_uint24(pos + 1)
            if self.data[pos] in (0x00, 0x01, 0x02):
                return ""
        end = self.data.find(b'\x00', pos)
        return self.data[pos:end].decode('gbk', errors='ignore')


if __name__ == '__main__':
    qq = IpQueryQQWry("qqwry.dat")
    r = qq.find_info("183.131.62.36")
    print(r)