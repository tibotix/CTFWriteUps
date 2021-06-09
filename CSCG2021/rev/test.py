import sys

# name at [esp+13AC]
# serial at [esp+1400]
# ascii_alphabet = [esp+13D0]

def generate_name_key(name):
    # name is the first 4 bytes in reverse
    name_key = [] # starting at [esp+0x28]
    for i in range(1, 0x270+1):
        name = ((name>>0x1e) ^ name) * 0x6c078965
        name += 1
        name_key.append(name)
    return name_key
    #[esp+0x20] = 0x270





def some_encryption(counter, nn, name_key):
    ecx = &counter # counter is address of counter
    edi = &counter
    [ebp-0x4] = &counter
    eax = counter
    if(counter==0x270):
        edx = &name_key[0] #&counter+0x8
        for i in range(counter):
            ecx = name_key[i+1] ^ name_key[i+2]
            ecx = ecx & 0x7fffffff
            ecx = ecx ^ name_key[i+1]
            eax = ecx
            if(bool(eax[0])):
                eax = 0x9908b0df
            else:
                eax = 0x0
            ecx = ecx>>0x1
            eax = eax ^ name_key[i+398]
            eax = eax ^ ecx
            name_key.append(eax)
        eax = counter
    elif(counter>=0x4e0): # DEAD CODE
        eax = name_key[-1] # 0x270
        push ebx
        ebx = &name_key[-1]
        for edi in range(0xe3, 0, -1):
            ecx = []
        
    
    nc = name_key[counter] # edx -> 0x9bc -> start of new generated above
    counter += 1
    &[counter] = counter
    #nn = encoded_name[0x4e1] # eax -> always 0xFFFFFFFF
    
    #x = local_encoded_name[0x4e1] # eax
    #x = x & (nc >> 0xb)
    #nc = ((nc ^ (local_encoded_name[0x4e1] & (nc >> 0xb))) & 0xFFFFFFFF) #correct

    #name_at_counter = (local_encoded_name[counter] >> 0xb) ^ (local_encoded_name[0x4e1] & (local_encoded_name[counter] >> 0xb))
    
    #x = nc & 0xff3A58Ad
    #x = (nc & 0xff3A58Ad) << 0x7
    #nc = (nc ^ ((nc & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF # correct
    #name_at_counter = name_at_counter ^ ((name_at_counter & 0xff3A58Ad) << 0x7))
    #x = ((nc & 0xff3A58Ad) << 0x7) & 0xffffdf8C
    #x = (((nc & 0xff3A58Ad) << 0x7) & 0xffffdf8C) << 0xF
    #nc = (nc ^ ((nc & 0xffffdf8C) << 0xF)) & 0xFFFFFFFF # correct
    #name_at_counter = name_at_counter ^ ( ((name_at_counter & 0xff3A58Ad) << 0x7) & 0xffffdf8C) << 0xf )
    
    #ret_val = nc >> 0x12
    #ret_val = ret_val ^ nc
    # ret_val = (name_at_counter>>0x12) ^ name_at_counter
    #return (nc>>0x12) ^ nc
    return (((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) & 0xffffdf8C) << 0xF)) & 0xFFFFFFFF)>>0x12) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) ^ ((((nc ^ (nn & (nc >> 0xb)) & 0xFFFFFFFF) & 0xff3A58Ad) << 0x7)) & 0xFFFFFFFF) & 0xffffdf8C) << 0xF)) & 0xFFFFFFFF)



def scramble_name(name, nn, name_key):
    counter = 0x270 #[esp+0x20]
    # name is the address of name -> [esp+13AC]
    for i in range(len(name)):
        eax = some_encryption(counter, nn, name_key)
        index = eax % 0xff
        name[i] = name[i] ^ alphabet_table[index]



def main():
    #demo script
    name = input("Name: ") # is filled up to 0x20
    serial = input("Serial: ") # max. 0x24
    nn = 0xFFFFFFFF
    name_key = generate_name_key(name[:4])
    scramble_name(name, nn, name_key)

    
    name_idx = len(name)
    if(name_idx>0):
        edx = 1 - &serial
        i = 0
        correct = True
        while(name_idx>0):
            edx = i % 0x9
            if(edx==0 and i>0): # every 9 rounds
                if(serial[i]!=0x2d): #0x2d = '-'
                    correct = False
            else:
                name_idx -= 1
                idx = name[name_idx] % 0x21
                #serial[i] = serial[i] ^ ascii_alphabet[idx]
                if(serial[i] != ascii_alphabet[idx]):
                    correct = False
            i += 1
        if(not correct): #al==0
            esi = "0xffffff" + [esp+0x13EA] # 3
            ecx = "0xffffff" + [esp+0x13DD] # P
            edx = "0xffffff" + [esp+0x13E7] # 0
            eax = "0xffffff" + [esp+0x13DC] # N
            keygen_print("NOP3NOP3")
            sys.exit(0)
    # this is GOALLL
    # will execute if
    #   1. name_idx <= 0
    #   2. serial[0x24] == ascii_alphabet[idx]; idx = name[0] % 0x21
    edx = [esp+0x1c] = "0xffffff" + [esp+0x13E7] # 0
    eax = "0xffffff" + [esp+0x13d2] # C
    ecx = esi = "0xffffff" + [esp+0x13df] # R
    edi = "0xffffff" + [esp+0x13ea] # 3
    [esp+0x18] = "0xffffff" + [esp+0x13e1] # T
    [esp+0x10] = "0xffffff" + [esp+0x13f1] # !
    keygen_print("C0RR3CT!")










        

