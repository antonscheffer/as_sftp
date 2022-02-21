whenever sqlerror exit failure
define compile_keymgmt_security="TRUE"
DECLARE
    l_cnt   NUMBER;
    l_cnt2  NUMBER;
BEGIN
    SELECT COUNT(*) INTO l_cnt
    FROM user_tables
    WHERE table_name IN ('AS_SFTP_KNOWN_HOSTS', 'AS_SFTP_PRIVATE_KEYS');
    IF l_cnt > 0 THEN
        SELECT COUNT(*) INTO l_cnt2
        FROM user_tab_columns
        WHERE table_name IN ('AS_SFTP_KNOWN_HOSTS', 'AS_SFTP_PRIVATE_KEYS')
            AND column_name = 'CURRENT_USER';
        IF l_cnt2 != l_cnt THEN
            raise_application_error(-20001, 'One or both of tables AS_SFTP_KNOWN_HOSTS and AS_SFTP_PRIVATE_KEYS exist but do not contain the new column CURRENT_USER. Rename or drop those tables, or manually alter them to add the new column. PK is optional');
        END IF;
    END IF;
END;
/
--
-- for conditional compilation. value of define "do_file" will be the script to run
COLUMN :file_name NEW_VALUE do_file NOPRINT
VARIABLE file_name VARCHAR2(128)
--
-- get the current_schema name into a define named compile_schema. Reuse our sqlplus variable/column
-- :file_name/do_file combo for the purpose
--
BEGIN
    :file_name := SYS_CONTEXT('USERENV','CURRENT_SCHEMA');
END;
/
SELECT :file_name FROM dual;
define compile_schema=&&do_file
prompt compiling in schema &&compile_schema
prompt

whenever sqlerror continue
prompt deploying table as_sftp_private_keys
@@as_sftp_private_keys.sql
prompt ok if table create fails because table already exists
prompt deploying table as_sftp_known_hosts
@@as_sftp_known_hosts
prompt ok if table create fails because table already exists
whenever sqlerror exit failure
--
prompt as_sftp.pks
@@as_sftp.pks
prompt as_sftp.pkb
@@as_sftp.pkb

DECLARE
    l_cnt NUMBER;
    l_can_compile BOOLEAN;
BEGIN
    IF '&&compile_keymgmt_security' = 'TRUE' THEN
$if dbms_db_version.ver_le_10 $then
        l_can_compile := FALSE;
$elsif dbms_db_version.ver_le_11 $then
        l_can_compile := FALSE;
$else
        -- dbms version 12 and higher have needed features
        select COUNT(*) INTO l_cnt
        FROM all_procedures
        WHERE object_type = 'PACKAGE' AND object_name = 'DBMS_RLS';
        IF l_cnt > 0 THEN
            l_can_compile := TRUE;
        ELSE
            l_can_compile := FALSE;
        END IF;
    ELSE
        l_can_compile := FALSE;
$end
    END IF;
    IF l_can_compile THEN
        :file_name := 'install_keymgmt_security.sql';
    ELSE
        :file_name := 'not_installing_keymgmt_security.sql';
    END IF;
END;
/
SELECT :file_name FROM dual;
prompt calling &&do_file
@@&&do_file


