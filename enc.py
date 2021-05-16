from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from tkinter import Tk, Button,Label,Frame, Entry, END

def cipherFunc():
    # aes=AES.new(hash.digest(),AES.MODE_ECB)
    passEncoded=passwordFd.get().encode('utf-8')
    hashSHA=SHA256.new(passEncoded).digest()
    aes=AES.new(hashSHA,AES.MODE_ECB)
    encrypted=aes.encrypt(plainTextFd.get()) # TODO: 16 wala masla
    # decrypted=aes.decrypt(encrypted)
    cipherTextFd.delete(0,END)
    cipherTextFd.insert(0,encrypted)
    #consoleLabel['text']=decrypted

def decipherFunc():
    # aes=AES.new(hash.digest(),AES.MODE_ECB)
    passEncoded=passwordFd.get().encode('utf-8')
    hashSHA=SHA256.new(passEncoded).digest()
    aes=AES.new(hashSHA,AES.MODE_ECB)
    # encrypted=aes.encrypt(plainTextFd.get()) # TODO: 16 wala masla
    encrypted=cipherTextFd.get()
    decrypted=aes.decrypt(encrypted)
    plainTextFd.delete(0,END)
    plainTextFd.insert(0,decrypted)
    #consoleLabel['text']=decrypted

window = Tk()

window.title("EcCryptApp")

# UI idea
# fds req : Password, plaintext, ciphertext
# Buttons : Encrypt, Decrypt

pframe=Frame(window,bd=2, bg='red')

# Password Fd
passwordFd = Entry(pframe)
passwordFd.insert(END, 'Type Password here')
passwordFd.pack()

# Plaintext Fd
plainTextFd = Entry(pframe,)
plainTextFd.insert(END, '1234567890ABCDEF')
plainTextFd.pack()

# Cipher Text Fd
cipherTextFd = Entry(pframe)
cipherTextFd.insert(END, 'Type Encrypted Text here')
cipherTextFd.pack()

# Encrypt Btn
buttonEncrypt = Button(pframe,text='Encrypt',command=cipherFunc)

# Decrypt Btn
buttonDecrypt = Button(pframe,text='Decrypt',command=decipherFunc)

consoleLabel = Label(window)
# frame.pack()
consoleLabel.pack()
buttonEncrypt.pack()
buttonDecrypt.pack()
pframe.pack()

window.mainloop()


#>>> from Crypto.Hash import SHA256

#>>>p='123456'

#>>> p.encode('utf-8')
#b'123456'

#>>> SHA256.new(p.encode('utf-8'))
#<Crypto.Hash.SHA256.SHA256Hash object at 0x7f74f714d390>
#>>> hash=SHA256.new(p.encode('utf-8'))

#>>> hash.digest()
#b'\x8d\x96\x9e\xefn\xca\xd3\xc2\x9a:b\x92\x80\xe6\x86\xcf\x0c?]Z\x86\xaf\xf3\xca\x12\x02\x0c\x92:\xdcl\x92'

#>>> from Crypto.Cipher import AES
#>>> AES.MODE_
#AES.MODE_CBC      AES.MODE_CFB      AES.MODE_CTR      AES.MODE_ECB      AES.MODE_OFB      AES.MODE_OPENPGP  AES.MODE_PGP      
#>>> aes=AES.new(hash.digest(),AES.MODE_ECB)
#>>> aes
#<Crypto.Cipher.AES.AESCipher object at 0x7f74f714d7f0>

#>>> aes.encrypt('abcdef')
#ValueError: Input strings must be a multiple of 16 in length
#>>> aes.encrypt('abcdef0000000000')
#b'\x87\xde\x1e\xbbF6 \xa5\xfb\n\x8dW:\xd7\x1f\x90'
#>>> ex=aes.encrypt('abcdef0000000000')

#>>> daes=AES.new(hash.digest(),AES.MODE_ECB)
#>>> daes.decrypt(ex)
#b'abcdef0000000000'
