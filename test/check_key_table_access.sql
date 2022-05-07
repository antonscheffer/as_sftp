-- do not expect results. only as_sftp package or sysdba can read
select * from as_sftp_known_hosts;
execute dbms_output.put_line(' ');
BEGIN
  as_sftp.open_connection( i_host => 'localhost', i_trust_server => true );
  as_sftp.close_connection;
END;
/
BEGIN
  as_sftp.open_connection( i_host => 'rhl1', i_trust_server => true );
  as_sftp.close_connection;
END;
/
BEGIN
    as_sftp.delete_priv_key(i_host => 'localhost', i_user => 'lee');
    as_sftp.insert_priv_key(i_host => 'localhost', i_user => 'lee', i_key => q'!-----BEGIN RSA PRIVATE KEY-----
put key here
-----END RSA PRIVATE KEY-----!'
);
END;
/
-- do not expect results. only as_sftp package or sysdba can read
select * from as_sftp_private_keys;

declare
  l_file blob;
  l_dir_listing as_sftp.tp_dir_listing;
begin
-- login overloaded with i_host to establish connection and use private key for login
  as_sftp.login( i_user => 'lee', i_host => 'localhost' );
-- connection now established. Look around
  as_sftp.set_log_level( 0 );
  dbms_output.put_line( as_sftp.pwd );
  l_dir_listing := as_sftp.read_dir( i_path => '.' );
  for i in 1 .. l_dir_listing.count
  loop
    dbms_output.put_line( l_dir_listing( i ).file_name );
  end loop;
-- create blob from text
  l_file := utl_raw.cast_to_raw( 'just a small test file for testing purposes.
It contains multiple lines.
This is the third.' );
--
-- transfer blob as file into current directory on remote host
  as_sftp.put_file( i_path => 'small_file.txt', i_file => l_file );
-- replace blob content to prove return transfer worked
  l_file := utl_raw.cast_to_raw( 'dummy' );
--  read the just created file 
  as_sftp.get_file( i_path => 'small_file.txt', i_file => l_file );
  dbms_output.put_line( utl_raw.cast_to_varchar2( l_file ) );
-- clean up and close connection
  dbms_lob.freetemporary( l_file );
  as_sftp.close_connection;
end;
/


BEGIN
/*
    as_sftp.insert_priv_key(i_host => 'rhl1', i_user => 'lee', i_key => q'!-----BEGIN OPENSSH PRIVATE KEY-----
put key here
-----END OPENSSH PRIVATE KEY-----!'
);
*/
    as_sftp.update_priv_key(i_host => 'rhl1', i_user => 'lee', i_key => q'!-----BEGIN OPENSSH PRIVATE KEY-----
put key here
-----END OPENSSH PRIVATE KEY-----!'
);
END;
/

declare
  l_file blob;
  l_dir_listing as_sftp.tp_dir_listing;
begin
-- login overloaded with i_host to establish connection and use private key for login
  as_sftp.login( i_user => 'lee', i_host => 'rhl1' );
-- connection now established. Look around
  as_sftp.set_log_level( 0 );
  dbms_output.put_line( as_sftp.pwd );
  l_dir_listing := as_sftp.read_dir( i_path => '.' );
  for i in 1 .. l_dir_listing.count
  loop
    dbms_output.put_line( l_dir_listing( i ).file_name );
  end loop;
-- create blob from text
  l_file := utl_raw.cast_to_raw( 'just a small test file for testing purposes.
It contains multiple lines.
This is the third.' );
--
-- transfer blob as file into current directory on remote host
  as_sftp.put_file( i_path => 'small_file.txt', i_file => l_file );
-- replace blob content to prove return transfer worked
  l_file := utl_raw.cast_to_raw( 'dummy' );
--  read the just created file 
  as_sftp.get_file( i_path => 'small_file.txt', i_file => l_file );
  dbms_output.put_line( utl_raw.cast_to_varchar2( l_file ) );
-- clean up and close connection
  dbms_lob.freetemporary( l_file );
  as_sftp.close_connection;
end;
/
