#!/usr/bin/python3
import os.path
import sys
import binascii
import abc
#import math

def num_bin( byte_num, endi ):
	#transform from bytes( little/big endian ) to int
	if endi:
		return int.from_bytes( byte_num, byteorder = 'little' );
	else:
		return int.from_bytes( byte_num, byteorder = 'big' );
#loading class
class Load_main( abc.ABC ):
	@abc.abstractmethod
	def __init__( self, filename ):
		pass;
	@abc.abstractmethod
	def __del__( self ):
		pass;
	@abc.abstractmethod
	def _ld_byte( self, nbyte ):
		pass;
	@abc.abstractmethod
	def _cut_head_gl( self ):
		pass;
	@abc.abstractmethod
	def _ld_head( self ):
		pass;
	@abc.abstractmethod
	def ld_packet( self ):
		pass;
class Load_pcap( Load_main ):
	def __init__( self, filename ):
		self._open_file = open( filename, 'rb' );
		#save size of file
		self._size = os.stat(filename).st_size;
		#save byte arangement in file
		self._order = self._cut_head_gl();
		#flag of end of file
		self.flag_eof = 1;	

	def __del__( self ):
		self._open_file.close();

	def _ld_byte( self, nbyte ):
		#load nbyte number of bytes
		if ( self._size - nbyte ) < 0:
			print ( 'unexpected end of file' );
			sys.exit( 2 );
		elif ( self._size - nbyte ) == 0:
			#normal end of file
			self.flag_eof = 0;
		self._size -= nbyte;
		return self._open_file.read( nbyte );

	def _cut_head_gl( self ):
		#cut global header from pcap file + set byte order
		#byte order
		num1 = self._ld_byte( 2 );
		num2 = self._ld_byte( 2 );
		#header remains
		tmp = self._ld_byte( 20 );
		if num1 < num2:
			return  0;
		else:
			return 1;
	def _ld_head( self ):
		#read packet header 
		tmp = self._ld_byte( 8 );
		oc = self._ld_byte( 4 );
		lng = self._ld_byte( 4 );

		#debug num octtets x actual lenght
		if ( oc != lng ):
			print ( 'warning number of octets != actual lenght' );
		if ( self._order ):
			return int( num_bin( lng, 1  ));
		else:
			return int( num_bin( lng, 0  ));
	def ld_packet( self ):
		# returt whole packet
		return self._ld_byte( self._ld_head() );		


# main
## nacteni jmena souboru a jeho kontrola
if len( sys.argv ) < 2:
	print ( 'no file to process' );
	sys.exit( 1 );

infname = sys.argv[1];
# exit program if file "filename" not exist
if not os.access( infname, os.R_OK ):
	print ( 'non readable/non exits file' );
	sys.exit( 1 );

##------debug--------------
a = Load_pcap( infname );
#b = Load_pcap( infname );

#f = open( 'zz.txt', 'wb' );
#f.write( a.ld_packet() );
print ( a._ld_head() );
#print( binascii.hexlify(a._ld_byte( 1 )) );



#processing
	#loop to trough array
	#sum,count min, max - 1st flag
	#protocol, data -> protocol data
	#asoc array(ipI,ipO,prot):data count
	

	#array end
	# average(sum,count)
#vystup

