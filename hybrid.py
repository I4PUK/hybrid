from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto import Random

#генерация ключа для Алисы

#генерируем ключ RSA на 2048 битов
privatekey = RSA.generate(2048)
#создаем файл для приватного ключа Алисы для записи в двочиной форме, курсор стоит в начале
f = open('aliceprivatekey.txt','wb')
#записывает в файл RSA ключ в формате PEM (текстовой)
f.write(bytes(privatekey.exportKey('PEM'))); f.close()
#создаем публичный ключ для Алисы
publickey = privatekey.publickey()
f = open('alicepublickey.txt','wb')
f.write(bytes(publickey.exportKey('PEM'))); f.close()

# генерация ключа для Боба
privatekey = RSA.generate(2048)
f = open('bobprivatekey.txt','wb')
f.write(bytes(privatekey.exportKey('PEM'))); f.close()
publickey = privatekey.publickey()
f = open('bobpublickey.txt','wb')
f.write(bytes(publickey.exportKey('PEM'))); f.close()

# создание подписи

#открываем файл для записи в двочином формате
f = open('message.txt','rb')
#записываем содержимое в plaintext
message = f.read(); f.close()
#импортиреум ранее созданный приватный ключ Алисы
privatekey = RSA.importKey(open('aliceprivatekey.txt','rb').read())
#хэшируем содержимое файла
myhash = SHA.new(message)
#преобразуем подпись в стандарт PKCS#1 v.1.5
signature = PKCS1_v1_5.new(privatekey)
signature = signature.sign(myhash)

# шифрование подписи
#импортиреум ранее созданный публичный ключ Боба
publickey = RSA.importKey(open('bobpublickey.txt','rb').read())
#Возвращает объект шифрования PKCS 1 OAEP_Cipher,
#который может использоваться для выполнения шифрования или дешифрования PKCS#1 OAEP.
#Возвращает объект шифрования PKCS 1 OAEP_Cipher, который может использоваться для выполнения шифрования или дешифрования PKCS#1 OAEP.
cipherrsa = PKCS1_OAEP.new(publickey)
sig = cipherrsa.encrypt(signature[:128])
sig = sig + cipherrsa.encrypt(signature[128:])
f = open('signature.txt','wb')
f.write(bytes(sig)); f.close()

file = open('message.txt', 'r').read()
print('Исходное сообщение: ', file)

# создается 256 битный сессионный ключ
sessionkey = Random.new().read(32) # 256 бит
# сообщение шифруется с помощью симметричного метода АЕС
f = open('message.txt', 'rb')
message = f.read(); f.close()
iv = Random.new().read(16) # 128 бит
#iv - вектор инициализации для шифрования и дешифрования, создаем новый AES шифр
obj = AES.new(sessionkey, AES.MODE_CFB, iv)
ciphertext = iv + obj.encrypt(message)
f = open('message.txt', 'wb')
f.write(bytes(ciphertext)); f.close()

# шифрование ключа сеанса с помощью RSA
publickey = RSA.importKey(open('bobpublickey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(publickey)
sessionkey = cipherrsa.encrypt(sessionkey)
f = open('sessionkey.txt','wb')
f.write(bytes(sessionkey)); f.close()


# дешифруем сессионный ключ
privatekey = RSA.importKey(open('bobprivatekey.txt','rb').read())
#Возвращает объект шифрования PKCS 1 OAEP_Cipher, который может использоваться для выполнения шифрования или дешифрования
cipherrsa = PKCS1_OAEP.new(privatekey)
f = open('sessionkey.txt','rb')
sessionkey = f.read(); f.close()
#дешифруем сессионный ключ
sessionkey = cipherrsa.decrypt(sessionkey)

# дешифруем сообщение
file = open('message.txt', 'r').read()
print('Зашифрованное сообщение: ', file)
f = open('message.txt','rb')
ciphertext = f.read(); f.close()
iv = ciphertext[:16]
obj = AES.new(sessionkey, AES.MODE_CFB, iv)
message = obj.decrypt(ciphertext)
#срезаем вектор инициализации и получаем исходное сообщение
message = message[16:]
f = open('message.txt','wb')
f.write(bytes(message)); f.close()


# расшифровываем подпись
f = open('signature.txt','rb')
signature = f.read(); f.close()
privatekey = RSA.importKey(open('bobprivatekey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(privatekey)
sig = cipherrsa.decrypt(signature[:256])
sig = sig + cipherrsa.decrypt(signature[256:])

# проверяем подпись
f = open('message.txt', 'rb')
message = f.read(); f.close()
publickey = RSA.importKey(open('alicepublickey.txt','rb').read())
myhash = SHA.new(message)
signature = PKCS1_v1_5.new(publickey)
test = signature.verify(myhash, sig)
file = open('message.txt', 'r').read()
print('Расшифрованное сообщение: ', file)

print('Совпадение подписей: ', test)