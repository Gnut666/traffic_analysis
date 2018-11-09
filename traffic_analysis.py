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
	def get_packet( self ):
		pass;
	@abc.abstractmethod
	def get_last_size( self ):
		pass;
	@abc.abstractmethod
	def get_flag_eof( self ):
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
		#set last size
		self._last_size = 0;

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
			return int( num_bin( lng, 1 ));
		else:
			return int( num_bin( lng, 0 ));
	def get_packet( self ):
		self._last_size = self._ld_head();
		# returt whole packet
		return self._ld_byte( self._last_size );
				
	def get_last_size( self ):
		return self._last_size;

	def get_flag_eof( self ):
                return self.flag_eof;

##-----processing-----

class  Processing_main( abc.ABC ):
	@abc.abstractmethod
	def __init__( self ):
		pass;
	@abc.abstractmethod
	def __del__( self ):
		pass;
	@abc.abstractmethod
	def write_report( self ):
		pass;

class Processing_pcap( Processing_main ):
	def __init__( self ):
		## load file name and make control
		if len( sys.argv ) < 2:
			print ( 'no file to process' );
			sys.exit( 1 );
		filename = sys.argv[ 1 ];
		# exit program if file "filename" not exist
		if not os.access( filename, os.R_OK ):
			print ( 'non readable/non exits file' );
			sys.exit( 1 );
		self.pcap = Load_pcap( filename );

	def __del__( self ):
		del self.pcap;
	def _proc_packet( self ):
		self.pcap.get_packet();
		#TODO protocool, address... 
		pass;
	def write_report( self ):
		size_min = 0;
		size_max = 0;
		#total size
		size_all = 0;
		packet_count = 0;
		while self.pcap.get_flag_eof():
			self._proc_packet();
			#print ( self.pcap.get_last_size() );
			last_size = self.pcap.get_last_size();
			packet_count += 1;
			if ( packet_count == 1 ):
				size_max = last_size;
				size_min = last_size;
			size_all += last_size;
			if ( size_max < last_size ):
				size_max = last_size;
			if ( size_min > last_size ):
				size_min = last_size;
		print ( size_min, size_max, size_all /  packet_count );
		return 1;

        #sum,count min, max - 1st flag
        #protocol, data -> protocol data
        #asoc array(ipI,ipO,prot):data count


        #array end
        # average(sum,count)
	



##------main------------

a = Processing_pcap();

##------debug--------------

#b = Load_pcap( infname );

a.write_report();
#print ( a.get_last_size());

#print ( a._ld_head() );
#f = open( 'zz.txt', 'wb' );
#f.write( a.ld_packet() );
#print( binascii.hexlify(a._ld_byte( 1 )) );



#vystup

