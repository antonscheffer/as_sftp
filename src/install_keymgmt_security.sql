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
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_SELECT_POLICY',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_SELECT_SECURITY',
                      'SELECT');
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_INSERT_POLICY',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_INSERT_SECURITY',
                      'INSERT'
                    ,TRUE -- needed because insert does not have where clause. check condition after insert
                );
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_UPDATE_POLICY',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_UPDATE_SECURITY',
                      'UPDATE');
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_DELETE_POLICY',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_DELETE_SECURITY',
                      'DELETE');
    --

    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_SELECT_POLICY_KH',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_SELECT_SECURITY_KH',
                      'SELECT');
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_INSERT_POLICY_KH',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_INSERT_SECURITY_KH',
                      'INSERT'
                    ,TRUE -- needed because insert does not have where clause. check condition after insert
                );
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_UPDATE_POLICY_KH',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_UPDATE_SECURITY_KH',
                      'UPDATE');
    DBMS_RLS.add_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_DELETE_POLICY_KH',
                      '&&compile_schema.', 'AS_SFTP_KEYMGMT_SECURITY.USER_DATA_DELETE_SECURITY_KH',
                      'DELETE');
END;
/
