#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>
#include <vector>

#define LINUX_ELF_OFFSET 0x400000

class BinLoader {
    public:
        BinLoader();
    protected:
        void sanity_check();
    private:
        std::vector<std::string> g_not_important_symbols = {"__stack_chk_fail", "__gmon_start__"};
};

BinLoader::BinLoader(){
}

def sanity_check(elf: lief.ELF.Binary) -> int:
    if elf.header.machine_type != lief.ELF.ARCH.x86_64:
        print("Only support x86_64 ELF")
        return 1

    # if not elf.is_pie:
        # print("Only PIE ELF")
        # return 2

    return 0

def is_dynamic(elf: lief.ELF.Binary) -> bool:
    return elf.has_section(".dynamic")

def patch_binary(elf: lief.ELF.Binary, system_map) -> None:
    assert sanity_check(elf) == 0

    if(is_dynamic(elf)):
        # We have to patch the .plt .got for nuttx libc location
        reloc = elf.relocations
        reloc = list(filter(lambda x: x.symbol.name not in NOT_IMPORTNAT_DYNAMIC_SYMBOLS, reloc))

        system_map = system_map.split("\n")
        system_map = list(filter(None, system_map))
        system_map_func_l = filter(lambda x: x.split(" ")[1].upper() == 'T', system_map)
        system_map_vari_l = filter(lambda x: x.split(" ")[1].upper() == 'B', system_map)
        system_map_func = {x.split(" ")[2]:int(x.split(" ")[0], 16) for x in system_map_func_l}
        system_map_vari = {x.split(" ")[2]:int(x.split(" ")[0], 16) for x in system_map_vari_l}

        # Functions
        for rel in reloc:
            name = rel.symbol.name

            if name in system_map_func:
                elf.patch_pltgot(rel.symbol, system_map_func[name])
                print("Found function " + rel.symbol.name + "\t\t patched with " + hex(system_map_func[name]))
                continue

            if name in system_map_vari:
                elf.patch_address(rel.address, system_map_vari[name], size=8)
                print("Found variable " + rel.symbol.name + " at " + hex(rel.address) + " \t\t patched with " + hex(system_map_vari[name]))
                continue

            print("Found unresolvable symbols")
            print(name)
            raise Exception("Found unresolvable symbols")

    else:
        # just load the file
        pass

def flat(elf, filename):

    ret = []

    # glibc wish to see __ehdr_start to point to the elf header
    # gnu-ld did hackly point it to LINUX_ELF_OFFSET, right before .text
    # Because Linux use mmap to load the elf into memory, the small header share
    # the same page with .text will also get mapped, and loader altogether. Neet!

    # Let's copy the header and make everyone a good day
    # Good job lief, having inconsistent names on phdr...
    size = elf.header.numberof_segments * elf.header.program_header_size + elf.header.header_size
    print("_ehdr_start copied, size: " + hex(size))
    with open(filename, "rb") as fil:
        ret += fil.read(size)

    # Let's load the LOAD segements
    segs = list(filter(lambda x: x.type == lief.ELF.SEGMENT_TYPES.LOAD, elf.segments))
    for seg in segs:

        seg_offset = seg.virtual_address - seg.file_offset - LINUX_ELF_OFFSET

        # We have to sort the sections, not always in ascending order in ELF file
        # Some sections might overlay with others, e.g. .tbss, .tdata
        secs = sorted(list(seg.sections), key=lambda x: x.offset)
        for sec in secs:
            print("{:25} {:>16} {:>16}".format(sec.name, hex(sec.offset + seg_offset), hex(sec.size)))
            if(len(ret) < (sec.offset + seg_offset + sec.size)):
                ret += [0] * ((sec.offset + seg_offset + sec.size) - len(ret))
            if sec.type != lief.ELF.SECTION_TYPES.NOBITS:
                ret[sec.offset + seg_offset:sec.offset + seg_offset + sec.size] = sec.content

    return array.array('B', ret).tostring()

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield  l[i:i + n]

class packet_types(IntEnum):
    PING = 0
    PONG = 1
    RETURN = 2
    LOAD = 3
    START = 4
    TRASH = 5

ATTR_NONE = 0
ATTR_MORE = 1

class UIO(object):
    def __init__(self, path):
        self.packet_header_format = "<HIII"

        self.SYSMAP_SIZE = 0x20000
        self.DATA_SEGMENT_SIZE = 0x100000
        self.HEADER_SIZE = struct.calcsize(self.packet_header_format)
        self.AVAILABLE_SIZE = self.DATA_SEGMENT_SIZE - self.HEADER_SIZE

        self.file = os.open(path, os.O_RDWR)
        self.control_segment = mmap.mmap(self.file, 4096)
        self.data_segment = mmap.mmap(self.file, self.DATA_SEGMENT_SIZE + self.SYSMAP_SIZE, offset=4096, access=mmap.ACCESS_WRITE )

    def get_system_map(self):
        self.data_segment.seek(self.DATA_SEGMENT_SIZE)
        return self.data_segment.read(self.SYSMAP_SIZE).decode("ASCII").split("\x00\x00")[0]

    def send_irq(self):
        self.control_segment.seek(4)
        self.control_segment.write(b"\x00\x00\x00\x00")

    def wait_irq(self):
        os.read(self.file, 4)

    def ping(self):
        self.send_fragment(packet_types.PING, 0, 0, 0, b"")
        print("PINGED, WAIT PONG")
        pkt = self.recv_fragment()
        print("GOT PONG")
        if pkt[0] != packet_types.PONG:
            self.data_segment.seek(0)
            print(self.data_segment.read(self.HEADER_SIZE))
            raise Exception

    def recv_fragment(self):
        self.wait_irq()
        self.data_segment.seek(0)
        header = list(struct.unpack(self.packet_header_format,
                                self.data_segment.read(self.HEADER_SIZE)))

        data = b""
        if header[3] != 0:
            self.data_segment.seek(self.HEADER_SIZE)
            if header[2] & ATTR_MORE:
                data = self.data_segment.read(self.AVAILABLE_SIZE)
            else:
                data = self.data_segment.read(header[3] - self.AVAILABLE_SIZE * header[2])


        time.sleep(0.5)
        return header + [data];

    def send_fragment(self,
                      ptype: packet_types,
                      attribute: int,
                      fragment: int,
                      length: int,
                      data: bytes):
        header = struct.pack(self.packet_header_format, ptype, attribute, fragment, length)
        data = header + data
        self.data_segment.seek(0)
        self.data_segment.write(data)
        self.send_irq()
        time.sleep(0.5)

    def send(self, ptype: packet_types, data: bytes):
        print("Sending length:", hex(len(data)))
        # Data segmentation
        frags = list(chunks(data, self.AVAILABLE_SIZE))
        for index, c in enumerate(frags[:-1]):
            print("Sending Index", index, " length ", len(data))
            self.send_fragment(ptype, ATTR_MORE, index, len(data), c)
            print("WAIT PONG")
            pkt = self.recv_fragment()
            print("GOT PONG")
            if pkt[0] != packet_types.PONG:
                self.data_segment.seek(0)
                print(self.data_segment.read(self.HEADER_SIZE))
                raise Exception

        print("Sending Last")
        self.send_fragment(ptype, ATTR_NONE, len(frags) - 1, len(data), frags[-1])
        pkt = self.recv_fragment()
        if pkt[0] != packet_types.PONG:
            self.data_segment.seek(0)
            raise Exception

    def recv(self):
        ptype  = ""
        data = b""
        while True:
            pkt = self.recv_fragment()
            ptype = pkt[0]
            data += pkt[4]


            self.send_fragment(packet_types.PONG, ATTR_NONE, 0, 0, b"")

            if not (pkt[1] & ATTR_MORE):
                break

        return (ptype, data)

    def invoke(self, ptype: packet_types, data: bytes):
        self.send(ptype, data)
        pkt = self.recv()
        if pkt[0] != packet_types.RETURN:
            raise Exception
        return pkt[1]

    def start_binary(self, path, entry, argv):
        basename = os.path.basename(path)
        # get the required size to load the binary
        size = os.path.getsize(path)
        print("Allocating PCB and sending PROG_BITS")
        print("Loading binary")
        f = os.open(path, os.O_RDONLY)
        with contextlib.closing(mmap.mmap(f, size, prot=mmap.PROT_READ)) as m:
            ret = self.invoke(packet_types.LOAD, m.read(size))
            prg_id = struct.unpack("<I", ret)[0]

        os.close(f)

        print("Kickstart program", prg_id)
        # prepare argc, argv
        argv = [basename] + argv
        argc = len(argv)
        ll_argv = bytes([len(argv[0]) + 2]) + reduce(lambda x, y: x + bytes([len(y) + 1]) + y, map(lambda z: z.encode("ASCII") + b"\x00", argv))
        data = struct.pack("<III", prg_id, entry, argc) + ll_argv
        self.send(packet_types.START, data)

    def close(self):
        self.control_segment.close()
        self.data_segment.close()
        os.close(self.file)


def print_usage() -> None:
    print("Usage: loader.py <uio device> <elf file> ...")


def __main__() -> None:
    if len(sys.argv) < 3:
        print_usage()
        exit(1)

    elf_filename = sys.argv[2]
    out_filename = "/tmp/patched." + os.path.basename(elf_filename) + ".bin"
    uio_device = sys.argv[1]

    uio = UIO(uio_device)

    print("Testing Communication...")
    uio.ping()

    elf = lief.parse(elf_filename)
    patch_binary(elf, uio.get_system_map())

    # gnu.hash change size after we patched the binary
    # This might cause the phdr to grow in size, causing incorrect
    # mapping of of the __ehdr_start.
    # Let's eliminate this guy, whom might not exist
    try:
        elf.remove_section(".gnu.hash")
    except:
        pass

    # save a patched elf for reference
    elf.write("patched")

    # flat the elf to a binary and write to a tmp file
    with open(out_filename, "wb") as f:
        f.write(flat(elf, elf_filename))

    # Load it vis uio/ivshmem
    print("Loading program...")
    print(hex(elf.header.entrypoint))
    uio.start_binary(out_filename, elf.header.entrypoint, sys.argv[3:])

    uio.close()

__main__()

