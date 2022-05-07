-- must clear anything from a possibleprior install
@@uninstall_keymgmt_security.sql
--
prompt as_sftp_keymgmt_security.pks
@@as_sftp_keymgmt_security.pks
prompt as_sftp_keymgmt_security.pkb
@@as_sftp_keymgmt_security.pkb
GRANT EXECUTE ON as_sftp_keymgmt_security TO public;
-- if you do not have this priv, comment it out and have the DBA do it
CREATE OR REPLACE PUBLIC SYNONYM as_sftp_keymgmt_security FOR &&compile_schema..as_sftp_keymgmt_security ;
BEGIN
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_PRIVATE_KEYS'
                        ,policy_name        => 'USER_DATA_SELECT_POLICY'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_SELECT_SECURITY'
                        ,statement_types    => 'SELECT'
                        -- if you want to allow a user who is granted access to the table to
                        -- see everything in the record except the key
                        --,sec_relevant_cols    => 'KEY'
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_PRIVATE_KEYS'
                        ,policy_name        => 'USER_DATA_INSERT_POLICY'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_INSERT_SECURITY'
                        ,statement_types    => 'INSERT'
                        ,update_check       => TRUE -- needed because insert does not have where clause. check condition after insert
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_PRIVATE_KEYS'
                        ,policy_name        => 'USER_DATA_UPDATE_POLICY'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_UPDATE_SECURITY'
                        ,statement_types    => 'UPDATE'
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_PRIVATE_KEYS'
                        ,policy_name        => 'USER_DATA_DELETE_POLICY'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_DELETE_SECURITY'
                        ,statement_types    => 'DELETE'
                       );
    --

    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_KNOWN_HOSTS'
                        ,policy_name        => 'USER_DATA_SELECT_POLICY_KH'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_SELECT_SECURITY_KH'
                        ,statement_types    => 'SELECT'
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_KNOWN_HOSTS'
                        ,policy_name        => 'USER_DATA_INSERT_POLICY_KH'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_INSERT_SECURITY_KH'
                        ,statement_types    => 'INSERT'
                        ,update_check       => TRUE -- needed because insert does not have where clause. check condition after insert
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_KNOWN_HOSTS'
                        ,policy_name        => 'USER_DATA_UPDATE_POLICY_KH'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_UPDATE_SECURITY_KH'
                        ,statement_types    => 'UPDATE'
                       );
    DBMS_RLS.add_policy(object_schema       => '&&compile_schema.'
			,object_name        => 'AS_SFTP_KNOWN_HOSTS'
                        ,policy_name        => 'USER_DATA_DELETE_POLICY_KH'
			,function_schema    => '&&compile_schema.'
                        ,policy_function    => 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_DELETE_SECURITY_KH'
                        ,statement_types    => 'DELETE'
                       );
END;
/
