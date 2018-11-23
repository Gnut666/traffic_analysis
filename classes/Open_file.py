
class Open_file( ):

	def __init__( self, filename, mode ):
		try:
			self.op_file = open( filename, mode );
		except PermissionError:
			print ( 'non readable file' );
			sys.exit( 1 );
		except OSError:
			print ( 'non exist file' );
			sys.exit( 5 );
	def __del__( self ):
		try:
			self.op_file.close();
		except AttributeError:
			pass;
	def get_file_obj( self ):
		return self.op_file;
