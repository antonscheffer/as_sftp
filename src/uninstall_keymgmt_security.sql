whenever sqlerror continue
BEGIN
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_SELECT_POLICY');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_INSERT_POLICY');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_UPDATE_POLICY');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_PRIVATE_KEYS', 'USER_DATA_DELETE_POLICY');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_SELECT_POLICY_KH');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_INSERT_POLICY_KH');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_UPDATE_POLICY_KH');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    BEGIN
        DBMS_RLS.drop_policy('&&compile_schema.', 'AS_SFTP_KNOWN_HOSTS', 'USER_DATA_DELETE_POLICY_KH');
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
END;
/
DROP PUBLIC SYNONYM as_sftp_keymgmt_security;
DROP PACKAGE as_sftp_keymgmt_security;
whenever sqlerror exit failure
