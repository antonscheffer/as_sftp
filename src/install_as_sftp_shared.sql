whenever sqlerror exit failure
-- name the schema containing as_sftp. Can be the same schema into which this is deployed
define AS_SFTP_SCHEMA=lee
prompt as_sftp_shared.pks
@@as_sftp_shared.pks
prompt as_sftp_shared.pkb
@@as_sftp_shared.pkb
prompt as_sftp_shared_login.pls
@@as_sftp_shared_login.pls

