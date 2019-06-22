#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import os, argparse
from io import open
from time import time
import hashlib
import base64



parser = argparse.ArgumentParser ()

# Se relacionan las opciones que tienen cada uno de los algoritmos

	#opción principal
parser.add_argument("-cs" , help="Algoritmo CESAR" , action="store_true")
parser.add_argument("-vgn" , help="Algoritmo VIGENERE" , action="store_true")
	
	#opción a desplegar de acuero con la selección
parser.add_argument("-a" , help="Despliega ayuda del algoritmo seleccionado" , action="store_true")
parser.add_argument("-c" , help="opcion para cifrar" , action="store_true")
parser.add_argument("-d" , help="opcion para descifrar" , action="store_true")
#parser.add_argument("-b64" , help= "opcion para cifrar en base 64" , action="store_true")
parser.add_argument("-texto" , type=str , help="nombre del archivo del texto a cifrar o descifrar" , default=os.getcwd() , required=False)
parser.add_argument("-txtclave", type=str, help="nombre del archivo que contiene la clave", default=os.getcwd() , required=False)
args=parser.parse_args()

if args.cs == False and args.vgn == False and args.c == False and args.d == False:
        print("""
      ------------------UNIVERSIDAD AUTONOMA DE OCCIDENTE---------------------
      ---------------------Algoritmos Criptograficos--------------------------
    |                                                                         |
    |     Sintaxis: python3 ./proyectofinal.py <algoritmo>                    |
    |                                                                         |
    |     -cs      :Algoritmo de Cesar                                        |
    |     -vgn    :Algoritmo de Vigenere                                      |
    |                                                                         |
    |       consultar ayuda de un algoritmo determinado:                      |
    |       sintaxis: python ./proyectofinal.py < algoritmo >                 |
    |                                                                         |
    |   Introducciòn a la criptografia.                                       |
    |   Profesor: Msc.Siler Amador Donado.                                    |
    |   Semestre 2019-1.                                                      |
    |  Elaborado por: Vanessa Muñoz      vanessa.munoz_loaiza@uao.edu.co      |
    |                 Sandra Sepulveda   slsepulveda@uao.edu.co               |
    |                                                                         |   
    |   El codigo fuente, los archivos de texto utilizados y las claves de    |
    |   cada algoritmo se encuentra en el siguiente repositorio:              |
    |   Enlace de github                                                      |
    |-------------------------------------------------------------------------|
        """)

if args.cs == True and args.a == True or args.cs == True and args.c == False and args.d == False:

		print ("""
     ..........................UNIVERSIDAD AUTONOMA DE OCCIDENTE................................
     ...............Algoritmo por sustitucion monoalfabetico de Cesar...........................
    |                                                                                           |
    |   Sintaxis:python ./proyectofinal.py -cs <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave> |
    |                                                                                           |
    |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>                                 |
    |                  -d para descifrar el archivo <ArchivoEntrada>                            |
    |                                                                                           |
    |     <ArchivoEntrada>: nombre del archivo de entrada                                       |
    |     <ArchivoClave>  :nombre del archivo que contiene la clave                             |
    |                                                                                           |
    |      si <opcion> es -c, el archivo de salida es <ArchivoEntrada>                          |
    |               , que cambia a la extension .cif                                            |
    |      si <opcion> es -d, el archivo de salida es <ArchivoSalida>                           |
    |               ,  que cambia a la extension .dec                                           |
    |                                                                                           |
    |   El archivo que contiene la clave debe contener las letras normal sin espacios           |
    |   El resultado del cifrado proyectara el hash del texto en claro y el resultado           |
    |   del descifrado proyectara el hash del archivo descifrado es decir del archivo .dec      |
    |                                                                                           |
    |  Ejemplos:                                                                                |
    |  Cifrar:    ./proyectofinal.py -cs -c -texto quijote.txt -txtclave claveCesar.txt         |
    |  Descifrar: ./proyectofinal.py -cs -d -texto quijote.cif -txtclave claveCesar.txt         |
    |                                                                                           |
    |  Elaborado por: Vanessa Muñoz      vanessa.munoz_loaiza@uao.edu.co                        |
    |                 Sandra Sepulveda   slsepulveda@uao.edu.co                                 |
    |-------------------------------------------------------------------------------------------|
        """)

if args.vgn == True and args.a == True or args.vgn == True and args.c == False and args.d == False:

    	print("""
        .......................UNIVERSIDAD AUTONOMA DE OCCIDENTE.............................
        ............Algoritmo por polialfabetico periodico vigenere .........................
    |                                                                                              |
    | Sintaxis:python ./proyectofinal.py -vgn <opcion> -texto <ArchivoEntrada> -txtclave <ArchivoClave>     |
    |                                                                                              |
    |     <opcion> : -c para cifrar el archivo <ArchivoEntrada>                                    |
    |                  -d para descifrar el archivo <ArchivoEntrada>                               |
    |                                                                                              |
    |     <ArchivoEntrada>: nombre del archivo de entrada                                          |
    |     <ArchivoClave>  :nombre del archivo que contiene la clave                                |
    |                                                                                              |
    |      si <opcion> es -c, el archivo de salida es <ArchivoEntrada>                             |
    |               , que cambia a la extension .cif                                               |
    |      si <opcion> es -d, el archivo de salida es <ArchivoEntrada>                             |
    |               ,  que cambia a la extension .dec                                              |
    |                                                                                              |
    |   El archivo que contiene la clave debe contener las letras normal, sin espacios             |                                                                  |
    |   El resultado del cifrado proyectara el hash del texto en claro y el resultado              |
    |   del descifrado proyectara el hash del archivo descifrado es decir del archivo .dec         |
    |                                                                                              |
    |  Ejemplos:                                                                                   |
    |  Cifrar:    ./proyectofinal.py -vgn -c -texto quijote.txt -txtclave claveVgn.txt             |
    |  Descifrar: ./proyectofinal.py -vgn -d -texto quijote.cif -txtclave claveVgn.txt             |
    |                                                                                              |
    |  Elaborado por: Vanessa Muñoz      vanessa.munoz_loaiza@uao.edu.co                           |
    |                 Sandra Sepulveda   slsepulveda@uao.edu.co                                    |
    |----------------------------------------------------------------------------------------------|
        """)

# Cálculo del hash
def calcularHash ():
	filename = '/root/Desktop/Proyecto-Cesar-Vigenere/' + args.texto
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())
# Leer archivo de entrada
def archivoEntrada():
	mensaje = open(args.texto , 'r' , encoding = "ISO-8859-1")
	mensaje = mensaje.read().strip()
	return mensaje

# Cargar clave vigenere
def claveVgn ():
	clave = open(args.txtclave,'r')
	clave = clave.read()
	clave = clave + clave[0]
	return clave

# Cálculo del tiempo total de ejecución
def calcularTiempo ():
	tiempo_final = time()
	tiempo_total = tiempo_final-tiempo_inicial
	print("Tiempo total: ", tiempo_total)
	
#Crear archivo
def createFile(mensaje, args):
    salida = args.texto
    punto = salida.index(".")
    salida = salida[0:punto] + ".txt"
    cifra = open(salida, "w+")
    cifra.write(mensaje)

def readFile(archivo):
    f = open(archivo, "r")
    return f.read().strip()

def rotaciones ():
    clave = open(args.txtclave,'r')
    clave = clave.read().strip()
    return clave


def cifrarcesar(mensaje, rotaciones, salida):
    
    rotaciones= str(rotaciones())
    #Nota: también se puede importar a string y usar ascii_letters y ascii_uppercase
    alfabeto = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+/=ñÜ«ÏÙÃÀ][%_?¿+=ñÑ "
    longitud_alfabeto = len(alfabeto)
    codificado = ""
    for letra in mensaje:
        #if not letra.isalpha() or letra.lower() == 'ñ':
            #codificado += letra
            #continue
        valor_letra = alfabeto.find(letra)
        # Suponemo sque es minúscula, así que esto comienza en 97(a) y se usará el alfabeto en minúsculas
        alfabeto_a_usar = alfabeto
    
        # Rotamos la letra
        posicion = (int(valor_letra) + int(rotaciones)) % longitud_alfabeto
    
        # Convertimos el entero resultante a letra y lo concatenamos
        codificado += alfabeto_a_usar[posicion]

    salida = args.texto
    punto = salida.index(".")
    salida = salida[0:punto] + ".cif"
    cifra = open(salida, 'w+')
    cifra.write(codificado)
    
    createFile(mensaje, args)

    return codificado


def descifrarcesar(mensaje, rotaciones, salida):
    rotaciones= str(rotaciones())
    #Nota: también se puede importar a string y usar ascii_letters y ascii_uppercase
    alfabeto = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+/=ñÜ«ÏÙÃÀ][%_?¿+=ñÑ "
    longitud_alfabeto = len(alfabeto)
    decodificado = ""

    for letra in mensaje:
        
        valor_letra = alfabeto.find(letra)
        # Suponemos que es minúscula, así que esto comienza en 97(a) y se usará el alfabeto en minúsculas
        alfabeto_a_usar = alfabeto

        # Rotamos la letra, ahora hacia la izquierda
        posicion = (int(valor_letra) - int(rotaciones)) % longitud_alfabeto

        # Convertimos el entero resultante a letra y lo concatenamos
        decodificado += alfabeto_a_usar[posicion] 

    salida = args.texto
    punto = salida.index(".")
    salida = salida[0:punto] + ".dec"
    cifra = open(salida, "w+")
    cifra.write(decodificado)

    return decodificado

#Alfabeto en ASCII
def ConvertirCaracteraAscii(caracter):
	return ord(caracter)

def ConvertirAsciiCaracter(ascii):
	return chr(ascii)
	

######### VIGENERE #########
if args.vgn == True and args.c == True:

	#cargamos el tiempo inicial y se lee el mensaje a cifrar
	tiempo_inicial = time()         # Función de tiempo inicial.
	archivoEntrada()
	#CALCULAR HASH
	calcularHash()
	#cargamos la clave
	claveVgn()
	
	caraEspecial = "Ü«ÏÙÃÀ][%3_?¿"
	conversion=0
	for letras in caraEspecial:
		conversion =  conversion + ConvertirCaracteraAscii(letras)

	#if args.b64 == True:
	mensaje = archivoEntrada()
	#Se codifica el mensaje en base64 con el estandar utf-8
	convert = mensaje.encode("utf-8")
	encoded = base64.b64encode(convert)
	codigo = encoded.decode("utf-8")
	#Alfabeto
	alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=][%_?"

	#Variables para crear la nueva clave y la clave total de cifrado
	clave_lista = []
	new_clave = ""
	residuo = ""
	clave = claveVgn()
	
	#Convierto el string de la clave a una lista, para eliminar errores "\n"
	for letras in clave:
		clave_lista.append(letras)
	clave_lista.remove("\n")
	posicion = []  # Variable para operar la letras y conformar la nueva clave
	comp = ""
	cifrado = ""
	msg_cifrado = ""

# Encuentro la posicion de cada una de las letras de la clave en el alfabeto
	for letras in clave_lista:
		posicion.append(alfabeto.index(letras))
# Conformo la nueva clave utilizada para cifrar con el algoritmo de vigenere clasico.
	for x in range (1, (len(clave)-1)):
		operacion = (posicion[x] - posicion[x-1] ) % len (alfabeto)
		new_clave = new_clave + alfabeto[operacion]
	long_key = len(new_clave)
	long_msg = len(codigo)

	# Completo la clave para cifrar el mensaje
	numero_key=long_msg//long_key
	
	# Conformo la clave total de cifrado
	clave_cifra = (new_clave*numero_key)
	residuo = long_msg%long_key
	clave_cifra = clave_cifra + new_clave[:residuo]

#CIFRANDO
	
	for x in range(0,long_msg):
		cifrado = (alfabeto.index(codigo[x]) + alfabeto.index(clave_cifra[x])) % len (alfabeto)
		msg_cifrado = msg_cifrado + alfabeto[cifrado]
	
	#ARCHIVO DE SALIDA
	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".cif"
	cifra = open(salida , 'w')
	cifra.write(msg_cifrado)
	#CALCULAR TIEMPO TOTAL
	calcularTiempo()

#DESCIFRANDO
if args.vgn == True and args.d == True:
#cargamos el tiempo inicial y se lee el mensaje a cifrar
	tiempo_inicial = time()         
	archivoEntrada()
	#cargamos la clave
	claveVgn()
	
	#Variables para crear la nueva clave y la clave total de descifrado
	clave_lista = []
	new_clave = ""
	residuo = ""
	clave = claveVgn()
	codigo = archivoEntrada()
	
	#Caracteres especiales
	caraEspecial = "Ü«ÏÙÃÀ][%3_?¿"
	conversion=""
	for letras in caraEspecial:
		conversion =  conversion + str(ConvertirCaracteraAscii(letras))
	
	#Convierto el string de la clave a una lista, para eliminar errores "\n"
	#print(conversion)
	
	for letras in clave:
		clave_lista.append(letras)
	clave_lista.remove("\n")
	
	#Alfabeto
	alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=][%_?"

	posicion = []  # Variable para operar la letras y conformar la nueva clave
	comp = ""
	descifrado = ""
	msg_descifrado = ""

# Encuentro la posicion de cada una de las letras de la clave en el alfabeto
	for letras in clave_lista:
		posicion.append(alfabeto.index(letras))

# Conformo la nueva clave utilizada para cifrar con el algoritmo de vigenere clasico.
	for x in range (1, (len(clave)-1)):
		operacion = (posicion[x] - posicion[x-1] ) % len (alfabeto)
		new_clave = new_clave + alfabeto[operacion]
	long_key = len(new_clave)
	long_msg = len(codigo)
	
	# Completo la clave para cifrar el mensaje
	numero_key=long_msg//long_key
	
	# Conformo la clave total de cifrado
	clave_cifra = (new_clave*numero_key)
	residuo = long_msg%long_key
	clave_cifra = clave_cifra + new_clave[:residuo]

#DESCIFRADO VIGENERE
	
	for x in range(0,long_msg):
			
		if (codigo[x] in alfabeto ):
			descifrado = (alfabeto.index(codigo[x]) - alfabeto.index(clave_cifra[x])) % len (alfabeto)
		
		msg_descifrado = msg_descifrado + alfabeto[descifrado]

	# convertimos el mensaje descifrado de base64 a codigo ascci
	convert = base64.b64decode(msg_descifrado)
	decoded = convert.decode("utf-8")		# elimina caracteres extra de la codificacion
	
	#Guardo el mensaje descifrado en un texto correspondiente
	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cifra = open(salida, "w",encoding="ISO-8859-1")
	cifra.write(decoded)
	
	#CALCULAR HASH
	filename = '/root/Desktop/Proyecto-Cesar-Vigenere/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())
	#CALCULAR TIEMPO TOTAL
	calcularTiempo()			

########CESAR########

if args.cs == True and args.c == True:
	
	#cargamos el tiempo inicial y se lee el mensaje a cifrar
	tiempo_inicial = time()         # Función de tiempo inicial.
	f = open(args.texto, "r")
	mensaje = f.read().strip()
	salida=""
	cifrarcesar = cifrarcesar(mensaje, rotaciones, salida)
    
	#ARCHIVO DE SALIDA
	createFile(mensaje, args)
	
	#CALCULAR TIEMPO TOTAL
	calcularTiempo()

######DESCIFRANDO DE CESAR######
if args.cs == True and args.d== True:

	#cargamos el tiempo inicial y se lee el mensaje a cifrar
	tiempo_inicial = time()         # Función de tiempo inicial.
	#Leer Archivo
	f = open(args.texto, "r")
	mensaje = f.read().strip()
	salida=""
	descifrarcesar = descifrarcesar(mensaje, rotaciones, salida)
	print(salida)
	
	salida = args.texto
	punto = salida.index(".")
	salida = salida[0:punto] + ".dec"
	cifra = open(salida, "w+")
	cifra.write(descifrarcesar)

	#CALCULAR HASH
	filename = '/root/Desktop/Proyecto-Cesar-Vigenere/' + salida
	hasher = hashlib.md5()
	with open(filename,"rb") as open_file:
		content = open_file.read()
		hasher.update(content)
	print ("Hash = ", hasher.hexdigest())
	
	#CALCULAR TIEMPO TOTAL
	calcularTiempo()			


			
