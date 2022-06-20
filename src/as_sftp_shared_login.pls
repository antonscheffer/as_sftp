CREATE OR REPLACE PROCEDURE as_sftp_shared_login(
         i_user         VARCHAR2
        ,i_host         VARCHAR2
        ,i_trust_server BOOLEAN := FALSE
        ,i_passphrase   VARCHAR2 := NULL
        ,i_log_level    pls_integer := null
) AS
BEGIN
    &&AS_SFTP_SCHEMA..as_sftp.login(
         i_user	        => i_user
        ,i_host	        => i_host
        ,i_trust_server	=> i_trust_server
        ,i_passphrase 	=> i_passphrase 
        ,i_log_level 	=> i_log_level 
    );
END as_sftp_shared_login;
/
