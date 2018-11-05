#!/usr/bin/python3
import os.path
import sys
import binascii

#loading class
class Load_pcap:
	
		#init exit program if file "filename" not exist
		def __init__( self, filename ):
			self.open_file = open( filename, 'rb')
		def ld_byte( self ): 
			return self.open_file.read(2);	
	
# main
## nacteni jmena souboru a jeho kontrola
if len( sys.argv ) < 2:
	print ( 'no file to process' );
	sys.exit( 1 );

infname = sys.argv[1];

if  not os.access( infname, os.R_OK ):
	print ( 'non readable/non exits file' );
	sys.exit( 1 );

a = Load_pcap( infname );

print ( binascii.hexlify(a.ld_byte()) );



#processing
	#loop to trough array
	#sum,count min, max - 1st flag
	#protocol, data -> protocol data
	#asoc array(ipI,ipO,prot):data count
	

	#array end
	# average(sum,count)
#vystup

