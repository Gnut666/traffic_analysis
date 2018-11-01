#!/usr/bin/python3
import os.path
import sys

#loading class
class Load_pcap:
	
		#init exit program if file "filename" not exist
		def __init__( self, filename ):
			if  os.path.isfile( filename ): 
				self.filename = filename;
			else:
				sys.exit(1);
		def pr( self ):
			return os.path.isfile( self.filename );
		
		

# main
##TD nacteni jmena souboru
name="out.pcap";
a = Load_pcap(name);
print(a.pr());


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

