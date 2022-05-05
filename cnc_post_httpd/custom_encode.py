from base64 import urlsafe_b64decode, urlsafe_b64encode, b85decode, b85encode
from Crypto.Util.strxor import strxor
import zlib



KEY = b'j&wkrln+3CHxypYiic8ODDoIoNxFqeS6HjEOQ0eXfCF2c8MWBC7UV6G7#F+hP0lhVf,d&M#r#.5k*nxOa9Cy7tR#ejeXX8nIjXMy+!kx!MG;:YXLP8c.JElCD1s.GgAS'
PAD = b'GIF89a\x01\x01\x01\x01\x01\x01\xE6'



def custom_decode(data):
  if data:
    keyk = KEY * len(data)
    keyk = keyk[:len(data)]
    data = b85decode(data)
    data = strxor(data,keyk[:len(data)])
    data = zlib.decompress(data)
    data = data[13:]
    data = data.decode().strip()
  return(data)

def custom_encode(data):
  if data:
    keyk = KEY * len(data)
    keyk = keyk[:len(data)]
    data = PAD+data
    data = zlib.compress(data)
    data = strxor(data,keyk[:len(data)])
    data = b85encode(data)
  return(data)
