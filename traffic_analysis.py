#!/usr/bin/python3
import os
import sys

def include( filename ):
	if os.path.exists( filename ):
		exec( open( filename ).read() );

# files to include
include( './classes/Open_file.py' );
include( './classes/Load_file.py' );

# functions
def num_bin( byte_num, endi ):
	#transform from bytes( little/big endian ) to int
	if endi:
		return int.from_bytes( byte_num, byteorder = 'little' );
	else:
		return int.from_bytes( byte_num, byteorder = 'big' );

def two_byte_num( part1, part2 ):
	# transform 2 byte into one, 
	# part1 XX__
	# part2 __XX
	return ( ( part1 * 256 ) + part2 );

def byte_part( byte, part ):
	# return half byte
	# 1 - first, 2 - second, other - error
	if part == 1:
		return byte >> 4;
	elif part == 2:
		return byte & 15;
	else:
		print( 'internal error' );
		sys.exit( 3 );

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

		## open output file for write + tests
		self.output = self._open_output( sys.argv[ 2 ] );

		self.last_protocol = 'null';
		self.tcp_connections = 0;
		self.adr_source = 'null';
		self.adr_desti = 'null';

	def __del__( self ):
		try:
			del self.pcap;
			self.output.close();
		except AttributeError:
			pass;
	def _open_output( self, output ):
		try:
			return open( output, 'w' );
		except PermissionError:
			print ( 'can not make output file' );
			sys.exit( 4 );
		except OSError:
			print ( 'disk full' );
			sys.exit( 6 );

	def _proc_packet( self ):
		packet = list( self.pcap.get_packet() );

		if  two_byte_num( packet[ 12 ], packet[ 13 ] ) == 2048 and byte_part( packet[ 14 ], 1 ) == 4 :
			# here is ipv4
			if packet[ 23 ] == 1:
				self.last_protocol = 'icmp';
			elif packet[ 23 ] ==  6:
				self.last_protocol = 'tcp';
				# if flag ACK and SYN is set it is new connection
				if packet[ ( byte_part( packet[ 14 ], 2 ) * 4 ) + 27 ] == 18:
					self.tcp_connections += 1;
			elif packet[ 23 ] == 17:
				self.last_protocol = 'udp';
			else:
				print( 'warning: odd packet' );
				return 0;
			# ip addresses
			self.adr_source = str( packet[ 26 ] ) +'.'+ str( packet[ 27 ] ) +'.'+ str( packet[ 28 ] ) +'.'+  str( packet[ 29 ] );
			self.adr_dest = str( packet[ 30 ] ) +'.'+ str( packet[ 31 ] ) +'.'+ str( packet[ 32 ] ) +'.'+  str( packet[ 33 ] );
			return 1;
		elif two_byte_num( packet[ 12 ], packet[ 13 ] ) == 2054:
			#arp
			#arp addresses
			self.adr_source = str( packet[ 28 ] ) +'.'+ str( packet[ 29 ] ) +'.'+ str( packet[ 30 ] ) +'.'+  str( packet[ 31 ] );
			self.adr_dest = str( packet[ 38 ] ) +'.'+ str( packet[ 39 ] ) +'.'+ str( packet[ 40 ] ) +'.'+  str( packet[ 41 ] );
			self.last_protocol = 'arp';
			return 1
		else:
			print( 'warning: odd packet' );
			return 0;

	def _kbyte_conver( self, byte ):
		# coverts nuber of bytes to kilobytes if is number big enough
		# return string
		if byte >= 1023:
			return  str( round( byte / 1024 )) + 'KB';
		else:
			return str( byte ) + 'B';

	def write_report( self ):
		#declarations
		size_min = 0;
		size_max = 0;
		#total size
		size_all = 0;
		packet_count = 0;
		packet_odd = 0;
		protocol_BCount = { "tcp":0, "icmp":0, "udp":0, "arp":0 };
		#tcp comunication summary
		com_sum = {};

		while self.pcap.get_flag_eof():
			if self._proc_packet() == 0:
				packet_odd += 1;
				continue;
			#min, max, all, count	
			last_size = self.pcap.get_last_size();
			if ( packet_count == 1 ):
				size_max = last_size;
				size_min = last_size;
			if ( size_max < last_size ):
				size_max = last_size;
			if ( size_min > last_size ):
				size_min = last_size;
			size_all += last_size;
			packet_count += 1;
			#protocol size
			protocol_BCount[ self.last_protocol ] += last_size;
			# comunication summary listing
			com_key = self.adr_source +' | '+ self.adr_dest +' | '+ self.last_protocol +' | '
			if com_key in com_sum:
				com_sum[ com_key ] += last_size;
			else:
				com_sum[ com_key ] = last_size;

		# write to file
		self.output.write( '# traffic analysis report\n' );
		self.output.write( '# ethernet frame size( minimum, maximum, average )\n' );
		self.output.write( '<frame_size>\n' );
		self.output.write( 'min ' + self._kbyte_conver( size_min ) + '\n' );
		self.output.write( 'max ' + self._kbyte_conver( size_max ) + '\n' );
		if  packet_count:
			self.output.write( 'avg ' + self._kbyte_conver( size_all / packet_count ) + '\n' );
		else:
			self.output.write( 'avg 0\n' );

		self.output.write( '# [kilo]bytes in each protocol\n' );	
		self.output.write( '<protocol_usage>\n' );
		for i in protocol_BCount:
			self.output.write( str( i ) + ' ' + self._kbyte_conver( protocol_BCount[ i ] ) + '\n' );

		self.output.write( '<dump_stats>\n' );
		self.output.write( '# number of unerecognized packets and number of tcp connections\n' );
		self.output.write( 'odd_packets ' + str( packet_odd ) + '\n' );
		self.output.write( 'tcp_connections ' + str( self.tcp_connections ) + '\n' )

		self.output.write( '# summary of communicating IP address through each protocol\n' );
		self.output.write( '# sending IP | receiver IP | protocol | amount of data [k]B\n' );
		self.output.write( '<com_sum>\n' );
		for a in com_sum:
                        self.output.write( str( a ) +  self._kbyte_conver( com_sum[ a ] ) + '\n' );

		return 1;
##------main------------

# parametr control
if len( sys.argv ) < 2:
	print ( 'no file to process' );
	sys.exit( 1 );
if len( sys.argv ) < 3:
	print ( 'no output file specified' );
	sys.exit( 1 );

# load input file
infile = sys.argv[ 1 ];
file = Load_pcap( infile );
# load output file
outfile = sys.argv[ 2 ];

print( ' !debug! ' );
sys.exit( 0 );

proc = Processing_pcap();
if proc.write_report():
	sys.exit( 0 );
