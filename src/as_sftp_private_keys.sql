-- when security is enabled, only the as_sftp_keymgmt package methods can access or manipulate records in this table
CREATE TABLE as_sftp_private_keys
(
    host            VARCHAR2(1000) NOT NULL
    ,id             VARCHAR2(128) NOT NULL
    ,current_user   VARCHAR2(128) NOT NULL
    ,key            CLOB NOT NULL
    ,CONSTRAINT as_sftp_private_keys_pk PRIMARY KEY(host, id, current_user)
);
