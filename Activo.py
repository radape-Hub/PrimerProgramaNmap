import argparse
import os
import sys
import platform
from datetime import datetime
import nmap
import logging
from colorama import init, Fore, Back, Style
init(autoreset= True)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s',
                    filename = 'fichero_log',
                    )
logging.debug('Comienza el programa')
logging.info('Procesando con normalidad')
logging.warning('Advertencia')

paraentrada = argparse.ArgumentParser(prog= "EquiposActivos", usage= '%(prog)s [options]',  description='%s activos en la red ' % "equipos".capitalize(), epilog="esto es como se detectan los equipos".capitalize(), formatter_class=argparse.RawTextHelpFormatter)
paraentrada.add_argument("-t", dest="segmento", help = "Indique el segmento a analizar de la forma xxx.xxx.xxx", required = True )
paraentrada.add_argument("-r", dest="rango", help= "Indique el rango del segmento solo ingrese dos numeros separados por comas", required=True)
segentrada = paraentrada.parse_args()
listaSeg= segentrada.rango.split(',')
ip= segentrada.segmento
ipDividida = ip.split('.')

comienzo = listaSeg[0]
fin = listaSeg[1]

if (platform.system()=="Windows"):
    ping = "ping -n 1"
else :
    ping = "ping -c 1"


tiempoInicio = datetime.now()
print("[*] El escaneo se está realizando desde",ip+ '.' +comienzo,"hasta",ip+'.'+fin)

with open ("puertos.txt") as f:
	data = f.readlines()



ini = int(comienzo)
final= int(fin)
nm = nmap.PortScanner()

for subred in range(ini, final+1):
	direccion = ip+'.'+str(subred)
	response = os.popen(ping+" "+direccion)


	for line in response.readlines():
		if ("ttl" in line.lower()):
			Ipactiva = direccion
			print(Fore.YELLOW+Back.BLACK+Style.BRIGHT+"La {} esta activa ".format(Ipactiva).center(20,'-'))

			for i in data:

				

				try:


					nm.scan(Ipactiva, i )
					act= nm[Ipactiva]['tcp'][int (i)]
					ex = act.items()
					print ('El puerto es: ',str(i).center(30,'-'))
					for clave, valor in ex:
						if clave == 'state':
							print (clave,'-->', valor)
						if clave == 'name':
							print (clave,'-->', valor)

				except:
					print (Fore.RED+"la {} No conecto en el puerto {}".format (Ipactiva, i))

				try:
					nombre = nm[Ipactiva]['vendor'].items()
					for mac, nom in nombre:
						print (Fore.GREEN+Style.BRIGHT+"El nombre es {1} y la MAC del equipo es: {0} ".format(mac , nom))
				
				except:
					print (Fore.RED+"No se pudo mostrar el nombre o Mac del equipo")

			break

			
			
            


tiempoFinal = datetime.now()
tiempo = tiempoFinal - tiempoInicio
print("[*] El escaneo ha durado %s"%tiempo)



