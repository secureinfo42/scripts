#!/usr/bin/env python3
# -*- coding: utf-8 -*-


#
# Imports
#

# sys.exit()
import sys

# getopt.getopt
from getopt import getopt

# base64.encodestring
import base64




#
# Variables globales
#

# Nom de l'application
APP="xor"




# Fonction ...: <string> complexify(key<string>,arg<string>)
#
# Variables ..: key= Clé, arg= Données à chiffrer
#
# Retourne ...: newkey= Nouvelle clé
#
# Description : Genère une clé au moins aussi longue que les données à chiffrer
#
#   === Données d'entrée
#   Longueur de 'arg' ..: 38
#   Valeur de 'arg' ....: ceci est un message privé à chiffrer
#
#   === Tour n° 1
#   Longueur de 'newkey': 13
#   Valeur de 'newkey' .: UEBzc3cwcmQ=
#
#   === Tour n° 2
#   Longueur de 'newkey': 29
#   Valeur de 'newkey' .: VUVCemMzY3djbVE9ClBAc3N3MHJk
#
#   === Tour n° 3
#   Longueur de 'newkey': 53
#   Valeur de 'newkey' .: VlVWQ2VtTXpZM2RqYlZFOUNsQkFjM04zTUhKawpQQHNzdzByZA==
#
#
# -----------------------------------------------------------------------------
#
def complexify(key,arg):

  newkey = ""
  i = 0
  # print "#\n#   === Données d'entrée"
  # print "#   Longueur de 'arg' ..:",len(arg)
  # print "#   Valeur de 'arg' ....: "+arg
  # print "#\n"
  while len(newkey) <= len(arg):
    i = i + 1
    # print "#   === Tour n°",i
    newkey = base64.encodestring(newkey + key)
    # print "#   Longueur de 'newkey':",len(newkey)
    # print "#   Valeur de 'newkey' .: "+newkey
  return( newkey.strip() )




# Fonction ...: <string> xor(arg<string>,key<string>,format<string>)
#
# Variables ..: arg= Données à chiffrer, key= Clé, format= Format d'affichage
#
# Retourne ...: enc= Données (dé)chiffrées
#
# Description : Chiffre les valeur ordinales des octets des données
#               avec l'opération XOR
#
# -----------------------------------------------------------------------------
#
def xor(arg,key):

  enc = ""

  for i in range(0,len(arg)):
    res = ord(arg[i]) ^ ord(key[i%len(key)])
    enc = enc + chr(res)
  return(enc)




# Fonction ...: <void> usage(err<int>)
#
# Variables ..: err= Numéro de code d'erreur de sortie du programme via exit()
#
# Retourne ...: -
#
# Description : Affichage de l'aide d'utilisation
#
# -----------------------------------------------------------------------------
#
def usage(err):
  print("""
Usage: %s <-s string|-f file> <-k password> [-z] [-o file]

    -s : string to crypt

    -f : file to crypt

    -o : file to write output

    -z : harden password by cumulative base64 encoding until the length
         of the password is greater than the content to encrypt

  """ % APP)
  sys.exit(err)




# Fonction ...: <void> error(err<int>)
#
# Variables ..: descr= description à afficher
#               err= Numéro de code d'erreur de sortie du programme via exit()
#
# Retourne ...: Sorts avec le code d'erreur fourni
#
# Description : Affichage d'un message d'erreur et sort du programme
#
# -----------------------------------------------------------------------------
#
def error(descr,err):
  print("\nError: " + descr + "\n")
  sys.exit(err)





# Variables ..: Les paramètres cités ci-dessus
#
# Retourne ...: Si la sortie est dans un fichier: : rien
#               Sinon affiche le résultat au format sélectionné
#
# Description : Programme principal
#
# -----------------------------------------------------------------------------
#
if __name__ == '__main__':

  out = ""
  key = ""
  operation = ""
  target = ""

  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  #
  # * On essaye de récupérer les arguments passés ... 
  #
  try:
    opts,args = getopt(sys.argv[1:],"zXCHRDIs:f:k:ho:")
    for o,a in opts:
      # Seule l'option -s ou ...
      if o == "-s":
        if target:
          usage
        target="string"
        arg = a
      # ... l'option -f doit être choisie
      if o == "-f":
        if target:
          usage
        target="file"
        arg = a
      if o == "-k":
        key = a
      if o == "-o":
        out = a
      if o == "-z":
        operation = "hardkey"
      if o == "-h":
        usage(0)

  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  #
  # * .. sinon on y arrive pas, on affichage l'aide
  #
  except:
    error("invalid arguments.",1)

  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  #
  # Si les arguments obligatoires ne sont pas définis
  # on affiche l'aide
  #
  if not ( key and arg and target ) : 
    usage(1)
    sys.exit(1)

  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  #
  # Si les données à chiffrer sont dans un fichier, on récupère son contenu
  #
  if target == "file":
    # On essaie de lire le fichier (il peut être binaire)
    try:
      fh = open(arg,"rb")
      buff = fh.read()
      fh.close()
    except:
      error("unable to read input file",1)

    # Reposition dans 'arg' le contenu de 'buff'
    # Pour éviter les opérations distinctes -> [2]
    arg = buff

  # Si ça n'est pas un fichier, et que ça n'est pas une chaine de caractère
  # (cas improbable), on gère l'erreur et on affiche l'aide
  elif target != "string":
    error("this is not a valid string",2)

  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  #
  # Opérations commune à toutes les options
  #

  # [1] -> Le renforcement ou non, de la clé est commune à tester dans
  # tous les cas
  if operation == "hardkey":
    key = complexify(key,arg)
    fh = open(out+".key","w")
    fh.write(key)
    fh.close()

  # [2] -> L'opération de chiffrement est commune à toutes les options
  enc = xor(arg,key)

  # [3] -> Si l'opération d'écriture dans un fichiers
  if out == "":
    print(enc)
  else:
    try:
      fh = open(out,"wb")
      fh.write(enc)
      fh.close()
    except:
      error("unable to write output file",1)

