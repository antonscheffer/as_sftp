create or replace package as_sftp
is
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
  --
  procedure open_connection
    ( i_host varchar2
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    );
  procedure open_connection
    ( i_host varchar2
    , i_trust_server boolean
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    );
  procedure open_connection
    ( i_host varchar2
    , i_fingerprint varchar2
    , i_port pls_integer := 22
    , i_excluded_kex_algos   varchar2 := null
    , i_preferred_kex_algos  varchar2 := null
    , i_excluded_encr_algos  varchar2 := null
    , i_preferred_encr_algos varchar2 := null
    , i_excluded_pkey_algos  varchar2 := null
    , i_preferred_pkey_algos varchar2 := null
    );

  procedure login( i_user varchar2, i_password varchar2 := null, i_priv_key varchar2 := null, i_passphrase varchar2 := null, i_log_level pls_integer := null );

    PROCEDURE login(
         i_user         VARCHAR2
        ,i_host         VARCHAR2
        ,i_trust_server BOOLEAN := FALSE
        ,i_passphrase   VARCHAR2 := NULL
        ,i_log_level    pls_integer := null
    );
    -- When keymgmt_security is activated (fine grained access control)
    -- These three methods are the only way to manipuate the data in the table as_sftp_private_keys
    -- other than to truncate it or do the task as sysdba.
    -- You cannot read the data at all as get_priv_key is a private function that only login() can call.
    --
    PROCEDURE insert_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
    PROCEDURE update_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB);
    PROCEDURE delete_priv_key(i_host VARCHAR2, i_user VARCHAR2);

  function pwd
  return varchar2;

  function read_dir( i_path varchar2 )
  return tp_dir_listing;

  function path_exists( i_path varchar2, i_check_for_dir boolean := null )
  return boolean;

  function file_exists( i_path varchar2 )
  return boolean;

  function dir_exists( i_path varchar2, i_check_for_dir boolean := null )
  return boolean;

  function remove_file( i_filename varchar2 )
  return boolean;

  function remove_directory( i_path varchar2 )
  return boolean;

  function create_directory( i_path varchar2 )
  return boolean;

  function rename_path( i_old_path varchar2, i_new_path varchar2, i_overwrite boolean := true )
  return boolean;

  function get_file( i_path varchar2, i_file in out nocopy blob )
  return boolean;

  procedure get_file( i_path varchar2, i_file in out nocopy blob );

  function get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  return boolean;

  procedure get_file( i_path varchar2, i_directory varchar2, i_filename varchar2 );

  function put_file( i_path varchar2, i_file blob )
  return boolean;

  procedure put_file( i_path varchar2, i_file blob );

  function put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 )
  return boolean;

  procedure put_file( i_path varchar2, i_directory varchar2, i_filename varchar2 );

  procedure close_connection;

  procedure set_log_level( i_level pls_integer );
end;
