"""
Connection to Xiaomi Kettle via BLE
Based on work of https://github.com/aprosvetova/xiaomi-kettle
"""
import sys
from bluepy.btle import UUID, Peripheral, DefaultDelegate
from time import sleep

def reverseMac(mac)->bytes:
  parts = mac.split(":")
  reversedMac = bytearray()
  leng = len(parts)
  for i in range(1,leng+1):
    reversedMac.extend(bytearray.fromhex(parts[leng-i]))
  return reversedMac

KEY1 = bytes([0x90, 0xCA, 0x85, 0xDE])
KEY2 = bytes([0x92, 0xAB, 0x54, 0xFA])
MAC = "AA:BB:CC:DD:EE:FF"
REVERSEDMAC = reverseMac(MAC)
PRODUCTID = 275
#Can be generated or sniff response from kettle to mi home request and use "shouldbetoken":
TOKEN = bytes ([0x01, 0x5C, 0xCB, 0xA8, 0x80, 0x0A, 0xBD, 0xC1, 0x2E, 0xB8, 0xED, 0x82])

class HandleNotificationDelegate(DefaultDelegate):
  def __init__(self):
    DefaultDelegate.__init__(self)

  def handleNotification(self, cHandle, data):
    if cHandle == 37:
      print("Authentication token response:")
      print("response:"+data.hex())
      print("token:" + TOKEN.hex())
      print("shouldbetoken:"+cipher(mixB(REVERSEDMAC, PRODUCTID), cipher(mixA(REVERSEDMAC, PRODUCTID), data)).hex())
    elif cHandle == 61:
      print("Status update:")
      print(data.hex())
    else:
      print(cHandle)
      print(data.hex())
    #TODO: Handle data

def printAllDescriptors(peripheral):
  descriptors=peripheral.getDescriptors()
  for descriptor in descriptors:
    print (descriptor)

def printAllServices(peripheral):
  services=peripheral.getServices()
  for service in services:
    print (service)
    
def printAllCharacteristics(peripheral):
  chList = peripheral.getCharacteristics()
  print ("Handle   UUID                                Properties")
  print ("-------------------------------------------------------"                       )
  for ch in chList:
    print ("  "+str(ch.getHandle()) +"   "+str(ch.uuid) +" " + ch.propertiesToString())

def mixA(mac, productID)-> bytes:
  return bytes([mac[0], mac[2], mac[5], (productID & 0xff), (productID & 0xff), mac[4], mac[5], mac[1]])

def mixB(mac, productID)-> bytes:
  return bytes([mac[0], mac[2], mac[5], ((productID >> 8) & 0xff), mac[4], mac[0], mac[5], (productID & 0xff)])

def cipherInit(key)->bytes:
  perm = bytearray()
  for i in range(0,256):
    perm.extend(bytes([i & 0xff]))
  keyLen = len(key)
  j = 0
  for i in range(0,256):
    j+= perm[i] + key[i%keyLen]
    j= j & 0xff
    perm[i], perm[j] = perm[j], perm[i]
  return perm

def cipherCrypt(input, perm)-> bytes:
  index1 = 0
  index2 = 0
  output = bytearray()
  for i in range(0,len(input)):
    index1=index1+1
    index1 = index1 & 0xff
    index2 += perm[index1]
    index2 = index2 & 0xff
    perm[index1], perm[index2] = perm[index2], perm[index1]
    idx = perm[index1] + perm[index2]
    idx = idx & 0xff
    outputByte = input[i] ^ perm[idx]
    output.extend(bytes([outputByte & 0xff]))

  return output

def cipher(key, input)-> bytes:
  perm = cipherInit(key)
  return cipherCrypt(input,perm)

def auth(p):
  p.setDelegate(HandleNotificationDelegate())
  authService= p.getServiceByUUID("fe95")
  authDescriptors = authService.getDescriptors()

#AUTH BEGIN
#print("init")
  p.writeCharacteristic(44, KEY1,"true")

#print("subscribe")
  authDescriptors[1].write(bytes([0x01,0x00]),"true")

#print("auth")
  print("First attempt:"+cipher(mixA(REVERSEDMAC, PRODUCTID), TOKEN).hex())
  p.writeCharacteristic(37, cipher(mixA(REVERSEDMAC, PRODUCTID), TOKEN),"true")

#print("waiting")
  if p.waitForNotifications(10.0):
    print("Auth received")
    
#print("finish auth")
  print("ending sequence:"+cipher(TOKEN, KEY2).hex())
  p.writeCharacteristic(37, cipher(TOKEN, KEY2),"true")

#print("read ver")
  p.readCharacteristic(42)
#AUTH END
#print("Auth END")
#Subscribe to current temperature
  controlService= p.getServiceByUUID("01344736-0000-1000-8000-262837236156")
  controlDescriptors = controlService.getDescriptors()

#print("subscribe status")
  controlDescriptors[3].write(bytes([0x01,0x00]),"true")

  while True:
    if p.waitForNotifications(10.0):
      #print("handling notfication")
      continue

  #print ("Waiting...")

p = Peripheral(MAC) 
#RESPONSE = bytes([...]) 
#for i in range(0,10000):
#  if(cipher(mixA(REVERSEDMAC,i),cipher(mixB(REVERSEDMAC,i),cipher(mixA(REVERSEDMAC,i),RESPONSE))).hex() == " ... "):
#    print("productID:"+i)
auth(p)