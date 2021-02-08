Some example usages of this package.
First of all make sure that you have the required ACL.

This package keeps track of the "fingerprint" of a SFTP-server in the table as_sftp_known_hosts.
This fingerprint is stored when you use the procedure open_connection with the "right" parameters.

Either, when you know the fingerprint
<pre><code>begin
  as_sftp.open_connection( i_host => 'localhost' 
                         , i_fingerprint => 'MD5:3d:7c:0f:95:44:5e:0a:eb:51:27:c8:58:87:43:d1:a1' );
  as_sftp.close_connection;
end;</code></pre>

Or
<pre><code>begin
  as_sftp.open_connection( i_host => 'localhost', i_trust_server => true );
  as_sftp.close_connection;
end;</code></pre>

After that first time you can use something like the next script to read a file from a SFTP-server.
<pre><code>declare
  l_file blob;
  l_dir_listing as_sftp.tp_dir_listing;
begin
  as_sftp.open_connection( i_host => 'localhost' );
  as_sftp.login( i_user => 'demo', i_password => 'demo' );
  as_sftp.set_log_level( 0 );
  dbms_output.put_line( as_sftp.pwd );
  l_dir_listing := as_sftp.read_dir( i_path => '.' );
  for i in 1 .. l_dir_listing.count
  loop
    dbms_output.put_line( l_dir_listing( i ).file_name );
  end loop;
  l_file := utl_raw.cast_to_raw( 'just a small test file for testing purposes.
It contains multiple lines.
This is the third.' ); 
  /* create a file in the current directory */
  as_sftp.put_file( i_path => 'small_file.txt', i_file => l_file );  
  /* create a file in a existing subdirectory of current directory */
--  as_sftp.put_file( i_path => 'src/small_file.txt', i_file => l_file );
  l_file := utl_raw.cast_to_raw( 'dummy' );
  /* read the just created file */  
  as_sftp.get_file( i_path => 'small_file.txt', i_file => l_file );  
  dbms_output.put_line( utl_raw.cast_to_varchar2( l_file ) );
  dbms_lob.freetemporary( l_file );
  as_sftp.close_connection;
end;</code></pre>


# Login using a private key is partly supported, i.e. only using a RSA and DSA/DSS private key.
As soon as I think that this package is used (lots of stars, lots of bug issues, lots of feature requests, lots of donations) I will extend that with ECDSA private keys.
