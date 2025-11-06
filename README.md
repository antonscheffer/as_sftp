# as_sftp
A plsql SFTP client package

Requirements:  
grant execute on utl_tcp to &lt;user&gt;  
grant execute on utl_file to &lt;user&gt;  
grant execute on dbms_crypto to &lt;user&gt;  
  
ACL to reach the SFTP-server  
Depending on your database version  
* 12.1 or higher  
<pre><code>begin  
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
end;</code></pre>
  
* 11.2  
<pre><code>begin  
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
    , is_grant    => true  
    , privilege   => 'connect'  
    );  
  dbms_network_acl_admin.assign_acl  
    ( acl         => 'as_sftp.xml'  
    , host        => 'localhost' -- name/ip-adress of SFTP-server   
    , lower_port => 22          -- this is the default port used for SFTP, change or extend range if needed  
    , upper_port  => 22  
    );  
  commit;  
end;</code></pre>
