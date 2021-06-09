import copy
import bitstring
bitstring.bytealigned = True



serial = b"BSHQ3YGB-SYGPM4A8-K09MP6J7-YMQ62FQ"

alphabet_table = [0x00, 0x1d, 0x30, 0x9f, 0x37, 0xc7,  0xc3, 0x1e, 0xe8, 0x2f, 0xe6, 0x85, 0xcf, 0x4d, 0x52, 0x3f, 0xff, 0xf8, 0xea, 0x9f, 0x3d, 0x73, 0x70, 0xa5, 0x5a, 0xde, 0x3b, 0x39, 0xb3, 0x31, 0x39, 0xa8, 0x8f, 0xe7, 0x65, 0xff, 0xa4, 0x59, 0x61, 0xc0,  0x68, 0x1e, 0xaa, 0x2b, 0x0e, 0xb0, 0xf9,  0x03, 0xf5, 0xa0, 0xb8, 0xab, 0x76, 0x5f, 0x58, 0x57, 0xeb, 0xff, 0x7d, 0x00, 0x4b, 0xe6, 0xf3, 0xfc, 0xc6, 0xc4, 0xe5, 0xbd, 0xdc, 0x48, 0xb7, 0xc4, 0x5e, 0xd8, 0x2d, 0xfd, 0xa6, 0x77, 0xb1, 0xf4, 0xd6, 0xde, 0x49, 0x19, 0x2a, 0x43, 0xfd, 0x9a, 0xda, 0x07, 0x39, 0x6e, 0x57, 0x11, 0x41, 0x61, 0x39, 0x29, 0x35, 0x53, 0xdb, 0xc0, 0x17, 0x55, 0x68, 0x2d,  0xff, 0x9b, 0x21, 0x0c, 0x2f, 0x8d, 0xe3, 0x45, 0x04, 0xfa, 0xa0, 0x60, 0xf9, 0x43, 0xad, 0x5d, 0x2d, 0xc5,  0xea, 0xfd, 0x02,  0x0a, 0x4e, 0x7d, 0xcc, 0xa4, 0xb3, 0x73, 0x07, 0xab, 0xd8, 0x70, 0x6c, 0x58, 0xf5, 0x40,  0x5f, 0x51, 0xd3, 0xf5,  0x31, 0xdd,  0x64, 0xc2, 0xae, 0x9c, 0x36, 0x04, 0xe1, 0x0d, 0x58, 0x00, 0xe5, 0x53, 0x23, 0x14, 0xb0, 0xa7, 0xd8, 0x41, 0xdd, 0x5d,  0x3f, 0x65, 0x9b, 0x93, 0xc2, 0x4d, 0xf7, 0x85, 0x37, 0xb7, 0x32, 0x49,  0x9b, 0xb3, 0x97, 0x4a, 0x1a, 0x36, 0x40,  0xd6,  0x20,  0xcc, 0x79,  0x4c, 0x48, 0xe3, 0x3f, 0x00, 0xe3, 0xd1, 0xaf, 0x48, 0x65, 0x51, 0x9a, 0xf7, 0x42, 0x7d, 0x15, 0xf3, 0x7d, 0x05, 0x0b, 0xfb, 0x76, 0x4c, 0xe8, 0xe3, 0xfe, 0x57, 0xea, 0x11, 0x61, 0xa9, 0x39, 0x26, 0x54, 0x9f, 0x30, 0x57, 0xa5, 0xd4, 0x9d, 0xc4, 0x20,  0x96, 0x82, 0xd6, 0xe0, 0x8f, 0x5c, 0x73, 0x32, 0x27, 0xac, 0x8c, 0x9d, 0x58, 0xe9, 0x3d, 0xb4, 0x30, 0xf8, 0x1e, 0x0f, 0x81, 0xd4, 0xd1]
ascii_alphabet = b"ABCDEFGHJKLMNPQRSTUWQYZ0123456789!"



def some_encryption(counter, nn, orig_name_key, name):
    #ecx = &counter # counter is address of counter
    #edi = &counter
    #[ebp-0x4] = &counter
    #eax = counter
    #name_key = [name] + orig_name_key
    #name_key = orig_name_key
    if(counter==0x270):
        #edx = &name_key[0] #&counter+0x8
        name_key = [name] + orig_name_key
        for i in range(counter):
            # 1.round : name[0] ^ name_key[0]
            # 2.round : name_key[0] ^ name_key[1]
            #print("name_key[i]: {0}".format(hex(name_key[i])))
            #print("name_key[i+1]: {0}".format(hex(name_key[i+1])))
            ecx = name_key[i] ^ name_key[i+1]
            #print("ecx: {0}".format(hex(ecx)))
            ecx = ecx & 0x7fffffff
            #print("ecx: {0}".format(hex(ecx)))
            ecx = ecx ^ name_key[i]
            #print("ecx: {0}".format(hex(ecx)))
            eax = ecx
            b = bool(bitstring.BitArray(uint=eax, length=4*8)[-1])
            #print("b: {0}".format(str(b)))
            if(b):
                eax = 0x9908b0df
            else:
                eax = 0x0
            ecx = ecx>>0x1
            #print("name_key[i+397]: {0}".format(hex(name_key[i+397])))
            #print("eax: {0}".format(hex(eax)))
            eax = eax ^ name_key[i+397]
            #print("ecx2 : {0}".format(hex(ecx)))
            #print("eax2: {0}".format(hex(eax)))
            eax = eax ^ ecx
            #print("[{0}] appening: {1}\n".format(hex(counter-i),hex(eax)))
            name_key.append(eax) # last one should be 0xe4d84708
        eax = counter
    elif(counter>=0x4e0): # DEAD CODE
        pass
        #eax = name_key[-1] # 0x270
        #push ebx
        #ebx = &name_key[-1]
        #for edi in range(0xe3, 0, -1):
        #    ecx = []
    else:
        name_key = orig_name_key
        
    #name_key = name_key[1:]
    nc = name_key[counter] # edx -> 0x9bc -> start of new generated above
    return name_key, (((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) & 0xffffdf8C) << 0xF)) & 0xFFFFFFFF)>>0x12) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) & 0xffffdf8C) << 0xF)) & 0xFFFFFFFF)



class Name():
    def __init__(self, initial_name):
        self.name = self._extend_name(list(initial_name.encode("utf-8")))

    def _extend_name(self, name):
        rel = len(name)
        for i in range(len(name), 0x20):
            name.append(name[i-rel])
        return name

    def get_name_key(self):
        name_key = [] # starting at [esp+0x28]
        name_iv = self.name_iv
        for i in range(1, 0x270):
            name_iv = ((name_iv>>0x1e) ^ name_iv) & 0xFFFFFFFF
            name_iv = (name_iv * 0x6c078965) & 0xFFFFFFFF
            name_iv += i
            name_key.append(name_iv)
        return name_key

    def scramble_name(self, name_key, counter=0x270, nn=0xFFFFFFFF):
        for i in range(len(self.name)):
            name_key, eax = some_encryption(counter, nn, name_key, self.name_iv)
            #print("eax: {0}".format(hex(eax)))
            index = eax % 0xff
            #print("index: {0}".format(hex(index)))
            #print("alphabet_table[index]: {0}".format(hex(alphabet_table[index+1])))
            self.name[i] = self.name[i] ^ alphabet_table[index+1]
            print("name[{0}] = {1}\n".format(str(i), hex(self.name[i])))
            counter += 1

    def calculate_serial(self):
        serial = b""
        for i in range(len(self.name)-1, 0, -1):
            if((len(serial)+1)%9 == 0 and i!=len(self.name)-1):
                serial += b'-'
            idx = self.name[i] % 0x21
            serial += int.to_bytes(ascii_alphabet[idx], 1, "little")
        return serial
                

    def _hex(self, bytes_):
        return "".join([hex(i)[2:] for i in bytes_])

    @property
    def hex(self):
        return self._hex(self.name)

    @property
    def name_iv(self):
        return bitstring.BitArray(hex=self._hex(self.name[:4][-1::-1])).uint



def keygen(name):
    print("name: {0}".format(str(name.hex)))
    name_key = name.get_name_key()
    print("name_key: {0}".format(str([hex(i) for i in name_key])))
    print("name before scrambling: {0}".format(str(name.hex)))
    name.scramble_name(name_key)
    print("name after scrambling: {0}".format(str(name.hex)))
    serial = name.calculate_serial()
    print("serial: {0}".format(str(serial)))
    
    


if(__name__ == "__main__"):
    name = input("Name: ")
    name = Name(name)
    keygen(name)
