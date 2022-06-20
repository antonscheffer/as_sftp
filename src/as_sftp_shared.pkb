create or replace package body as_sftp_shared
is
    PROCEDURE insert_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB)
    IS
    BEGIN
        &&AS_SFTP_SCHEMA..as_sftp.insert_priv_key(
            i_host  => i_host
            ,i_user => i_user
            ,i_key  => i_key
        );
    END insert_priv_key;
    PROCEDURE update_priv_key(i_host VARCHAR2, i_user VARCHAR2, i_key CLOB)
    IS
    BEGIN
        &&AS_SFTP_SCHEMA..as_sftp.update_priv_key(
            i_host  => i_host
            ,i_user => i_user
            ,i_key  => i_key
        );
    END update_priv_key;
    PROCEDURE delete_priv_key(i_host VARCHAR2, i_user VARCHAR2)
    IS
    BEGIN
        &&AS_SFTP_SCHEMA..as_sftp.delete_priv_key(
            i_host  => i_host
            ,i_user => i_user
        );
    END delete_priv_key;

end as_sftp_shared;
/
show errors
