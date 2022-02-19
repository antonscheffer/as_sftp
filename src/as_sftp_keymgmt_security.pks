CREATE OR REPLACE PACKAGE as_sftp_keymgmt_security
AS
    --
    -- These control access to records in the table as_sftp_private_keys
    --
    FUNCTION user_data_select_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2;
    FUNCTION user_data_insert_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2;
    FUNCTION user_data_update_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2;
    FUNCTION user_data_delete_security (owner VARCHAR2, objname VARCHAR2)
    RETURN VARCHAR2;
END as_sftp_keymgmt_security;
/
show errors
