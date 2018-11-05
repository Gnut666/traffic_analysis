#!/usr/bin/python3
import os.path
import sys
import binascii
import abc

#loading class
class Load( abc.ABC ):
	@abc.abstractmethod
	def ld_byte( self, nbyte ):
		pass;
	def cut_head_gl( self ):
		pass;
class Load_pcap( Load ):
	
	#init exit program if file "filename" not exist
	def __init__( self, filename ):
		self.open_file = open( filename, 'rb');
		self.order = self.cut_head_gl();
	#todo destruktor
	def ld_byte( self, nbyte ): 
		return self.open_file.read( nbyte );
	def cut_head_gl( self ):
		#byte order
		num1 = self.ld_byte( 2 );
		num2 = self.ld_byte( 2 );
		tmp = self.ld_byte( 20 );
		return num1 < num2;
	
# main
## nacteni jmena souboru a jeho kontrola
if len( sys.argv ) < 2:
	print ( 'no file to process' );
	sys.exit( 1 );

infname = sys.argv[1];

if  not os.access( infname, os.R_OK ):
	print ( 'non readable/non exits file' );
	sys.exit( 1 );

##------debug--------------
a = Load_pcap( infname );
b = Load_pcap( infname );

print( binascii.hexlify(a.ld_byte( 1 )) );
print( binascii.hexlify(a.ld_byte( 1 )) );



#processing
	#loop to trough array
	#sum,count min, max - 1st flag
	#protocol, data -> protocol data
	#asoc array(ipI,ipO,prot):data count
	

	#array end
	# average(sum,count)
#vystup

