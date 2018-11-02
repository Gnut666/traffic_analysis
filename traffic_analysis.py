#!/usr/bin/python3
import os.path
import sys

#loading class
class Load_pcap:
	
		#init exit program if file "filename" not exist
		def __init__( self, filename ):
			self.filename = filename;
		def pr( self ):
			return os.path.isfile( self.filename );
		
		

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
print( a.pr() );


	#loop to end of file
	##? must know size
	#save each packet to array

#processing
	#loop to trough array
	#sum,count min, max - 1st flag
	#protocol, data -> protocol data
	#asoc array(ipI,ipO,prot):data count
	

	#array end
	# average(sum,count)
#vystup

