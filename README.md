# as_sftp

A plsql SFTP client package

# Author

Anton Scheffer created and maintains the package *as_sftp*. 

This fork adds key management. It also optionally implements *Fine Grained Access Control* on the known hosts and
private keys tables. If you want to know more about why you might want that and how I came about implementing it,
see [this blog post](https://lee-lindley.github.io/oracle/sql/plsql/2022/01/22/Hiding-Data-Oracle.html).

# Content

- [Usage](#usage)
- [Types](#types)
- [Methods](#methods)
    - [open_connection](#open_connection)
    - [login](#login)
    - [close_connection](#close_connection)
    - [set_log_level](#set_log_level)
    - [Private Key Maintenance Procedures](#private-key-maintenance-procedures)
    - [Directory Methods](#directory-methods)
    - [File Transfer Methods](#file-transfer-methods)
- [Manage Private Keys](#manage-private-keys)
- [Requirements](#requirements)
- [Installation](#installation)
    - [install.sql](#installsql)
    - [install_as_sftp_shared.sql](#install_as_sftp_sharedsql)
    - [Configure Keys](#configure-keys)

# Usage

## open_connection

As on Unix implementations, *as_sftp* keeps track of the *fingerprint* of an SFTP-server in the table 
*as_sftp_known_hosts*. This fingerprint is stored when you use the procedure 
*open_connection* with the "right" parameters. Once a host is known, this step is no longer required
for that host (unless it moves).

### Known Fingerprint First Time

```sql
BEGIN
  as_sftp.open_connection( i_host => 'localhost'
                         , i_fingerprint => 'MD5:3d:7c:0f:95:44:5e:0a:eb:51:27:c8:58:87:43:d1:a1' );
  as_sftp.close_connection;
END;
```

### Trust Connection First Time

As an alternative to providing the *fingerprint* directly, you can trust the connection.

```sql
BEGIN
  as_sftp.open_connection( i_host => 'localhost', i_trust_server => true );
  as_sftp.close_connection;
END;
```

## Example Usage With Password

```sql
declare
  l_file blob;
  l_dir_listing as_sftp.tp_dir_listing;
begin
  as_sftp.open_connection( i_host => 'localhost' );
-- providing password directly 
  as_sftp.login( i_user => 'demo', i_password => 'demo' );
-- connection now established. Look around
  as_sftp.set_log_level( 0 );
  dbms_output.put_line( as_sftp.pwd );
  l_dir_listing := as_sftp.read_dir( i_path => '.' );
  for i in 1 .. l_dir_listing.count
  loop
    dbms_output.put_line( l_dir_listing( i ).file_name );
  end loop;
-- create a blob for test purposes
--
  l_file := utl_raw.cast_to_raw( 'just a small test file for testing purposes.
It contains multiple lines.
This is the third.' );
--
-- transfer blob as file into current directory on remote host
  as_sftp.put_file( i_path => 'small_file.txt', i_file => l_file );
-- create a file in a existing subdirectory of current directory. Assumes directory exists
--  as_sftp.put_file( i_path => 'src/small_file.txt', i_file => l_file );
-- replace blob content to prove return transfer worked
  l_file := utl_raw.cast_to_raw( 'dummy' );
--  read the just created file 
  as_sftp.get_file( i_path => 'small_file.txt', i_file => l_file );
  dbms_output.put_line( utl_raw.cast_to_varchar2( l_file ) );
-- clean up (happens automatically when session ends, but this is good practice)
  dbms_lob.freetemporary( l_file );
-- end the session
  as_sftp.close_connection;
end;
```

## Example Usage with Private Key

If you have installed private key management (See [Manage Private Keys](#manage-private-keys),
then you can avoid putting the password in your code. 

```sql
-- one time setup of key
begin
    as_sftp.insert_priv_key( i_host => 'localhost', i_user => 'demo', i_key => '-----BEGIN RSA PRIVATE KEY-----
key string==
-----END RSA PRIVATE KEY-----'
    );
end;
/
```

Using private keys combines the *open_connection* method into *login*.

```sql
declare
  l_file blob;
begin
-- login overloaded with i_host to establish connection and use private key for login
  as_sftp.login( i_user => 'demo', i_host => 'localhost' );
  as_sftp.set_log_level( 0 );
  dbms_output.put_line( as_sftp.pwd );
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
```

# Types

## tp_dir_listing

*as_sftp.tp_dir_listing* for obtaining directory listing information from remote server.

```sql
  type tp_dir_line is record
         ( file_name varchar2(32767)
         , long_name varchar2(32767)
         , is_directory boolean
         , file_size number
         , uid number
         , gid number
         , perm number
         , atime date
         , mtime date
         );
  type tp_dir_listing is table of tp_dir_line index by pls_integer;
```
# Methods

## open_connection

There are multiple overloaded variants of *open_connection* that logically distill to:

```sql
procedure open_connection(
     i_host                 VARCHAR2
    ,i_port                 PLS_INTEGER := 22
    ,i_trust_server         BOOLEAN  := FALSE
    ,i_fingerprint          VARCHAR2 := NULL
    ,i_excluded_kex_algos   varchar2 := null
    ,i_preferred_kex_algos  varchar2 := null
    ,i_excluded_encr_algos  varchar2 := null
    ,i_preferred_encr_algos varchar2 := null
    ,i_excluded_pkey_algos  varchar2 := null
    ,i_preferred_pkey_algos varchar2 := null
);
```

When using the private key variant of *login*, you will not need *open_connection* unless installing a *fingerprint*.

## login

### Using Password

```sql
procedure login( 
     i_user varchar2
    ,i_password varchar2        := null
    ,i_priv_key varchar2        := null
    ,i_passphrase varchar2      := null
    ,i_log_level pls_integer    := null 
);
```

### Using Private Key

```sql
PROCEDURE login(
     i_user         VARCHAR2
    ,i_host         VARCHAR2
    ,i_trust_server BOOLEAN     := FALSE
    ,i_passphrase   VARCHAR2    := NULL
    ,i_log_level    pls_integer := null
);

```

## close_connection

```sql
procedure close_connection;
```

## set_log_level

```sql
procedure set_log_level( i_level pls_integer );
```

## Private Key Maintenance Procedures

```sql
PROCEDURE insert_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
PROCEDURE update_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
PROCEDURE delete_priv_key(i_host VARCHAR2, i_user VARCHAR2);
```

## Directory Methods

```sql
function pwd return varchar2;
function read_dir( i_path varchar2 ) return tp_dir_listing;
function path_exists( i_path varchar2, i_check_for_dir boolean := null ) return boolean;
function file_exists( i_path varchar2 ) return boolean;
function dir_exists( i_path varchar2, i_check_for_dir boolean := null ) return boolean;
function remove_file( i_filename varchar2 ) return boolean;
function remove_directory( i_path varchar2 ) return boolean;
function create_directory( i_path varchar2 ) return boolean;
function rename_path( i_old_path varchar2, i_new_path varchar2, i_overwrite boolean := true ) return boolean;
```
## File Transfer Methods

```sql
function get_file( i_path varchar2, i_file in out nocopy blob ) return boolean;
procedure get_file( i_path varchar2, i_file in out nocopy blob );
function get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 ) return boolean;
procedure get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 );
function put_file( i_path varchar2, i_file blob ) return boolean;
procedure put_file( i_path varchar2, i_file blob );
function put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 ) return boolean;
procedure put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 );
```

# Manage Private Keys

If you have not included *Fine Grained Access Control* on the installation, you may perform DML 
on table *as_sftp_private_keys* directly. Otherwise, all key access is through package methods.
(You can use the methods even if you have not added *DBMS_RLS* policy.)

| Hiding Private Key Data Use Case |
|:--:|
| ![Hiding Data Use Case](images/hiding_data_use_case.gif) |

From a database login that needs to perform *as_sftp.login*, execute these procedures 
from package *as_sftp* to manage keys:

- *as_sftp.insert_priv_key*
- *as_sftp.update_priv_key*
- *as_sftp.delete_priv_key*

*i_user* is the sftp login account on the remote host.

You must install/manage the keys from the schema login that will use them. In the case of keys that
will be used by an application package or procedure, you must manage the keys from the procedure owner
schema. See [Deployment Diagram](images/deployment_diagram.gif).

```sql
    PROCEDURE insert_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
    PROCEDURE update_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
    PROCEDURE delete_priv_key(i_host VARCHAR2, i_user VARCHAR2);
```

For the optional *as_sftp_shared_login* facility, use package *as_sftp_shared* to configure keys.
Note that execute on *as_sftp_shared* is not normally granted to other schemas.
Only the standalone procedure *as_sftp_shared_login* is granted to using schemas.

- *as_sftp_shared.insert_priv_key*
- *as_sftp_shared.update_priv_key*
- *as_sftp_shared.delete_priv_key*

These have the same footprint as the ones in *as_sftp* (which they call).

# Requirements

*EXECUTE* privilege must be granted to the installation schema on

- UTL_TCP
- DBMS_CRYPTO

Also required is an Access Control List (ACL) to reach the SFTP-server. Depending on your database version  

- 12.1 or higher  

```sql
begin  
  dbms_network_acl_admin.append_host_ace  
    ( host       => 'localhost' -- name/ip-adress of SFTP-server   
    , lower_port => 22          -- this is the default port used for SFTP, change or extend range if needed  
    , upper_port => 22  
    , ace        => xs$ace_type( privilege_list => xs$name_list('connect')  
                               , principal_name => '&&compile_schema.' -- use your install schema name
                               , principal_type => xs_acl.ptype_db  
                               )  
   );  
  commit;  
end;
```

- 11.2  

```sql
begin  
  dbms_network_acl_admin.create_acl  
    ( acl          => 'as_sftp.xml'  
    , description  => 'Allow connections using UTL_TCP'  
    , principal    => '&&compile_schema.'  -- use your install schema name
    , is_grant     => true  
    , privilege    => 'connect'  
    );  
  dbms_network_acl_admin.add_privilege  
    ( acl         => 'as_sftp.xml'  
    , principal    => '&&compile_schema.'  -- use your install schema name
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
end;
```

If you are on Oracle 12.1 or higher and want to use *Fine Grained Access Control* to secure a private keys
table, your installation schema also needs *EXECUTE* on

- DBMS_RLS

It seems relatively common to grant *EXECUTE* on DBMS_RLS to Public.

For *Fine Grained Access Control* you will need either the privilege to create *Public Synonym* 
or the DBA will need to create one for you. This is commented upon in *src/install_keymgmt_security.sql*.

If you do not enable *Fine Grained Access Control* everything will still work fine; however, users will be able
to see and manipulate the content of tables *as_sftp_private_keys* and *as_sftp_known_hosts* depending on
their normal database access privileges. When you are trying
to debug a problem, that is not such a bad thing. You can turn it off and re-enable it with the anonymous block code 
that drops and adds policy
in *uninstall_keymgmt_security.sql* and *install_keymgmt_security.sql*, respectively.

# Installation

See [Requirements](#requirements) before attempting to install.

This fork includes a *Private Keys* table and login procedure.
You may install with or without *Fine Grained Access Control*.
If you install without it, be aware that anyone who can *SELECT* from that table can obtain the private keys. This
isn't too different from the situation on Unix except:

1. It is much more common on the database for users to have elevated privileges that give them the ability to SELECT ANY TABLE.
2. It is not uncommon to have a shared schema with multiple people having login privilege, at least in the test environment.

Private keys are tied to the Oracle *USER* account executing the login procedure when *as_sftp.login*
is called from an anonymous block.

When *as_sftp.login* is called from a package or stored procedure, the keys are tied to the schema owner of that procedure.
The privilege stack is not relevant. You can have a package
or procedure compiled with *AUTHID CURRENT_USER* that will continue to use the keys associated with the
procedure owner, regardless of who invokes it.

There is also a package named *as_sftp_shared* and a standalone procedure named *as_sftp_shared_login* 
that may be installed in the same schema or one or more
different schemas. Users/procedures with *EXECUTE* on *as_sftp_shared_login* gain the use of private keys tied to 
that package schema owner.  This allows for managing
private keys by application groups instead of, or in addition to, the executing User account or procedure owner.

The most common application deployment patterns will not require *as_sftp_shared_login*. Most will be content with
having the keys tied to the application schema owner for any package that invokes *as_sftp.login*.

| Deployment Diagram |
|:--:|
| ![Deployment Diagram](images/deployment_diagram.gif) |

## install.sql

Execute *install.sql* from the *src* directory with the deployment schema login.

If you have previously installed *as_sftp*, and the *as_sftp_known_hosts* table does not contain a column *CURRENT_USER*,
then the installation will exit with an error message. You must add the column manually.

If they do not already exist, *install.sql* creates tables

- *as_sftp_known_hosts*
- *as_sftp_private_keys*

It will not clobber existing tables. It then creates or replaces package *as_sftp*. 

If on Oracle version 12 or higher, it checks to see if the installation schema has
execute privilege on package *DBMS_RLS* (see [Requirements](#requirements)). If so, it will call *install_keymgmt_security.sql*
to install package *as_sftp_keymgmt_security*, create a public synonym for same, and add *DBMS_RLS* policy
for tables *as_sftp_private_keys* and *as_sftp_known_hosts*. 
If you do not have the privilege to create public synonym, comment that out
and have the DBA perform that step manually.

## install_as_sftp_shared.sql

If desired, execute *install_as_sftp_shared.sql* in the same or one or more additional schemas. Need
for this package is less common.

## Configure Keys

See [Manage Private Keys](#manage-private-keys) for instructions to create/update private keys.
