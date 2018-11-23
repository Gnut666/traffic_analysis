
import os
import abc

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
		
		self.open_file = open( filename, 'rb' );
		
		#save size of file
		self.size = os.stat(filename).st_size;
		#save byte arangement in file
		self.order = self._cut_head_gl();
		#flag of end of file
		self.flag_eof = 1;
		#set last size
		self.last_size = 0;

        def __del__( self ):
                try:
                        self.open_file.close();
                except AttributeError:
                        pass;
        def _ld_byte( self, nbyte ):
                #load nbyte number of bytes
                if ( self.size - nbyte ) < 0:
                        print ( 'unexpected end of file' );
                        sys.exit( 2 );
                elif ( self.size - nbyte ) == 0:
                        #normal end of file
                        self.flag_eof = 0;
                self.size -= nbyte;
                return self.open_file.read( nbyte );

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
                if ( self.order ):
                        return int( num_bin( lng, 1 ));
                else:
                        return int( num_bin( lng, 0 ));

        def get_packet( self ):
                self.last_size = self._ld_head();
                # returt whole packet
                return self._ld_byte( self.last_size );

        def get_last_size( self ):
                return self.last_size;

        def get_flag_eof( self ):
                return self.flag_eof;
