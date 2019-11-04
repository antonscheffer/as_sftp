# as_sftp
A plsql SFTP client package

Requirements:
grant execute on utl_tcp to <user>
grant execute on dbms_crypto to <user>
  
ACL to reach the SFTP-server
Depending on your database version
12.1 or higher
begin
  dbms_network_acl_admin.append_host_ace
    ( host       => 'localhost' -- name/ip-adress of SFTP-server 
    , lower_port => 22          -- this is the default port used for SFTP, change or extend range if needed
    , upper_port => 22
    , ace        => xs$ace_type( privilege_list => xs$name_list('connect')
                               , principal_name => 'HR' -- use your Oracle user
                               , principal_type => xs_acl.ptype_db
                               )
   );
  commit;
end;

11.2
begin
  dbms_network_acl_admin.create_acl
    ( acl          => 'as_sftp.xml'
    , description  => 'Allow connections using UTL_TCP'
    , principal    => 'HR'  -- use your Oracle user
    , is_grant     => true
    , privilege    => 'connect'
    );
  dbms_network_acl_admin.add_privilege
    ( acl         => 'as_sftp.xml'
    , principal    => 'HR'  -- use your Oracle user
    , is_grant    => false
    , privilege   => 'connect'
    );
  dbms_network_acl_admin.assign_acl
    ( acl         => 'as_sftp.xml'
    , host        => 'localhost' -- name/ip-adress of SFTP-server 
    , lower_port => 22          -- this is the default port used for SFTP, change or extend range if needed
    , upper_port  => 22
    );
  commit;
end;
