CREATE TABLE AS_SFTP_KNOWN_HOSTS
(
    HOST            VARCHAR2(1000 CHAR) NOT NULL
    ,FINGERPRINT    VARCHAR2(100 CHAR) NOT NULL
    ,current_user   VARCHAR2(128 CHAR)
    ,CONSTRAINT as_sftp_known_hosts_pk PRIMARY KEY(host, current_user)
);

