'''
Por: David A. Mena
Codigo: 00215169
OS Windows 10
Programa que detecta los mac addresses de todos los dispositivos presentes en una red local.
Existe un mac address para ethernet y otro para wlan para cada computadora
Imprime uno de estos dependiendo de la opcion seleccionada en un archivo de texto
Determina el fabricante de la tarjeta de red, sea para ethernet o wlan
Da un porcentaje de la distribución de los fabricantes
'''
import sys
from scapy.all import srp, Ether, ARP, conf
import datetime
import urllib.request as weblib
import json
import codecs
import operator

# Main
if __name__ == "__main__":

    #Options and usr input
    try:
        print("Program that determines all the Mac Adresses within a given network (LAN or WLAN).")
        print("Also finds out the manufacturer of each newtwork card\nand makes an analysis of the data.")

        interface = input("\nEnter desired interface (Wi-Fi or Ethernet): ")
        ips = input("Enter range of IPs to Scan for (Ip/Mask): ")
        tout= input("Enter timeout:")
    #Keyboard exception
    except KeyboardInterrupt:
        print ("\n User requested shutdown")
        print ("Quiting...")
        sys.exit(1)


    option = "0"
    while(option != "1" and option != "2"):
        option = input("\nSelect the desired output option. Console print of mac addresses and analysis (1)."
                   "\nPrint mac addresses and ips on a text file (2):")

    # Loading msg
    print ("\n Scanning...\n")

    conf.verb = 0

    # Mensaje broadcast protocolo ARP
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout= int(tout), iface=interface, verbose=False)

    # print ( ans.summary() )
    # Necesary information
    timeStamp = time.time()
    strTimeStamp = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y.%m.%d.%H.%M.%S')
    apellidos = "MENA_MADRID_"
    mode = ""

    #Option (1) print
    if(option == "1"):
        url = "https://macvendors.co/api/" # Use a web API
        fabricantes = []

        setMacAdd = set()
        # print in console mac address, manufacturer and IP
        print(ips)
        for s, r in ans: # halla el mac address a traves de la direccion IP
            strMacAdd = r.sprintf(r'%Ether.hwsrc%')
            #Evitar mac address repetidos
            if strMacAdd not in setMacAdd:
                setMacAdd.add(strMacAdd)
                # determine manufacturer
                request = weblib.Request(url+strMacAdd, headers={'User-Agent' : "API Browser"})
                response = weblib.urlopen( request )
                # json object in str
                bytesToStr = codecs.getreader("utf-8")
                jsonResponse = json.load(bytesToStr(response))
                # get the mac address Manufacturer as string from the json obj
                strManufacturer = jsonResponse['result']['company']
                fabricantes.append(strManufacturer)

                # print in format
                print(r.sprintf('%Ether.hwsrc%' + '\t' + strManufacturer))

        print("\nPercentage per Manufacturer")
        # Porcentaje de los fabricantes
        setFabricantes = set(fabricantes)
        listQuantities = []
        totalQuantity = 0
        for name in setFabricantes:
            repeted = fabricantes.count(name)
            # print(name + "\t" + "#:"+ str(repeted) )
            totalQuantity = totalQuantity + repeted
            listQuantities.append(repeted)

        print( "Total " + str(totalQuantity) + " device(s)."  )
        # transform quantities to percentages
        lsPercentage = []
        for num, name in zip(listQuantities, setFabricantes):
            lsPercentage.append(round (num*100/totalQuantity , 2))
            #print (name + "\t" + str( round (num*100/totalQuantity , 2) ) + "%")

        # dictionary(tuple, float) for sorting
        dict = dict(zip( zip(setFabricantes, listQuantities) , lsPercentage))

        # sorts dictionary by value and reverse it
        dictByValue = sorted(dict.items(), key=operator.itemgetter(1), reverse=True)

        #Print dictionary ordered by value
        for nameNum, percent  in dictByValue:
            print ("{}% : {} device(s)\t{} ".format(percent, nameNum[1], nameNum[0] ))


    # Option (2) print in file
    if( option == "2"):
        if( interface == "Wi-Fi"):
            mode = "WLAN"
        elif (interface == "Ethernet"):
            mode = "LAN"
        with open(apellidos + mode +"_" + strTimeStamp + "_" + tout + "ms" ".txt", 'w') as newFile:
                newFile.write(ips)
                newFile.write("\n")
                for s, r in ans:
                    newFile.write(r.sprintf('%Ether.hwsrc%' + '\t' + r'%ARP.psrc%'))
                    newFile.write("\n")
        # Finished msg
        print ("\n Process Done! ")
